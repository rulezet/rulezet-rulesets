rule TTP_XOR_MULT_DOSStub_5a42 {
  strings:
    $key_5a42 = { 0e 2a [2] 7a 32 [2] 3d 30 [2] 7a 21 [2] 34 2d [2] 38 27 [2] 2f 2c [2] 34 62 [2] 09 }

  condition:
    any of them
}