rule TTP_XOR_MULT_DOSStub_0142 {
  strings:
    $key_0142 = { 55 2a [2] 21 32 [2] 66 30 [2] 21 21 [2] 6f 2d [2] 63 27 [2] 74 2c [2] 6f 62 [2] 52 }

  condition:
    any of them
}