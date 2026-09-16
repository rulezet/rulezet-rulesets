rule TTP_XOR_MULT_DOSStub_1d42 {
  strings:
    $key_1d42 = { 49 2a [2] 3d 32 [2] 7a 30 [2] 3d 21 [2] 73 2d [2] 7f 27 [2] 68 2c [2] 73 62 [2] 4e }

  condition:
    any of them
}