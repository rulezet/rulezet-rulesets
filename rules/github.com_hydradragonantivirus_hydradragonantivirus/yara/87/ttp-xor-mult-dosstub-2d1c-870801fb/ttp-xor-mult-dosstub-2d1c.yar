rule TTP_XOR_MULT_DOSStub_2d1c {
  strings:
    $key_2d1c = { 79 74 [2] 0d 6c [2] 4a 6e [2] 0d 7f [2] 43 73 [2] 4f 79 [2] 58 72 [2] 43 3c [2] 7e }

  condition:
    any of them
}