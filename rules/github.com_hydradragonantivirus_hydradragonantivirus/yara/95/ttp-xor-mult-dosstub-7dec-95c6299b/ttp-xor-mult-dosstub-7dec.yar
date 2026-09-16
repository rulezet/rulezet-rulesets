rule TTP_XOR_MULT_DOSStub_7dec {
  strings:
    $key_7dec = { 29 84 [2] 5d 9c [2] 1a 9e [2] 5d 8f [2] 13 83 [2] 1f 89 [2] 08 82 [2] 13 cc [2] 2e }

  condition:
    any of them
}