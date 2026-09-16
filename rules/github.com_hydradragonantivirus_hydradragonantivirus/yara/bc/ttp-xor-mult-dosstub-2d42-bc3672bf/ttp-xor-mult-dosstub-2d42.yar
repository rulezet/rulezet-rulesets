rule TTP_XOR_MULT_DOSStub_2d42 {
  strings:
    $key_2d42 = { 79 2a [2] 0d 32 [2] 4a 30 [2] 0d 21 [2] 43 2d [2] 4f 27 [2] 58 2c [2] 43 62 [2] 7e }

  condition:
    any of them
}