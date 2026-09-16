rule TTP_XOR_MULT_DOSStub_3a42 {
  strings:
    $key_3a42 = { 6e 2a [2] 1a 32 [2] 5d 30 [2] 1a 21 [2] 54 2d [2] 58 27 [2] 4f 2c [2] 54 62 [2] 69 }

  condition:
    any of them
}