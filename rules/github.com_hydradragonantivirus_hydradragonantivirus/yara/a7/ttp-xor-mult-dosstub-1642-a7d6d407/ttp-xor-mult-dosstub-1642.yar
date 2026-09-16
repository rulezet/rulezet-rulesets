rule TTP_XOR_MULT_DOSStub_1642 {
  strings:
    $key_1642 = { 42 2a [2] 36 32 [2] 71 30 [2] 36 21 [2] 78 2d [2] 74 27 [2] 63 2c [2] 78 62 [2] 45 }

  condition:
    any of them
}