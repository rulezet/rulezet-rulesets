rule TTP_XOR_MULT_DOSStub_5342 {
  strings:
    $key_5342 = { 07 2a [2] 73 32 [2] 34 30 [2] 73 21 [2] 3d 2d [2] 31 27 [2] 26 2c [2] 3d 62 [2] 00 }

  condition:
    any of them
}