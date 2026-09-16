rule TTP_XOR_MULT_DOSStub_2d72 {
  strings:
    $key_2d72 = { 79 1a [2] 0d 02 [2] 4a 00 [2] 0d 11 [2] 43 1d [2] 4f 17 [2] 58 1c [2] 43 52 [2] 7e }

  condition:
    any of them
}