rule TTP_XOR_MULT_DOSStub_3642 {
  strings:
    $key_3642 = { 62 2a [2] 16 32 [2] 51 30 [2] 16 21 [2] 58 2d [2] 54 27 [2] 43 2c [2] 58 62 [2] 65 }

  condition:
    any of them
}