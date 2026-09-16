rule TTP_XOR_MULT_DOSStub_2dec {
  strings:
    $key_2dec = { 79 84 [2] 0d 9c [2] 4a 9e [2] 0d 8f [2] 43 83 [2] 4f 89 [2] 58 82 [2] 43 cc [2] 7e }

  condition:
    any of them
}