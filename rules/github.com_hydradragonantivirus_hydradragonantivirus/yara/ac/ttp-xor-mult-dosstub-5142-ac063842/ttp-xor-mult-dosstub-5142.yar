rule TTP_XOR_MULT_DOSStub_5142 {
  strings:
    $key_5142 = { 05 2a [2] 71 32 [2] 36 30 [2] 71 21 [2] 3f 2d [2] 33 27 [2] 24 2c [2] 3f 62 [2] 02 }

  condition:
    any of them
}