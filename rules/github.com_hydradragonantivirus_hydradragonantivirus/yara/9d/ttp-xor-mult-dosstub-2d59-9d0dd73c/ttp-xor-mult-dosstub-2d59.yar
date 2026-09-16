rule TTP_XOR_MULT_DOSStub_2d59 {
  strings:
    $key_2d59 = { 79 31 [2] 0d 29 [2] 4a 2b [2] 0d 3a [2] 43 36 [2] 4f 3c [2] 58 37 [2] 43 79 [2] 7e }

  condition:
    any of them
}