rule TTP_XOR_MULT_DOSStub_4a42 {
  strings:
    $key_4a42 = { 1e 2a [2] 6a 32 [2] 2d 30 [2] 6a 21 [2] 24 2d [2] 28 27 [2] 3f 2c [2] 24 62 [2] 19 }

  condition:
    any of them
}