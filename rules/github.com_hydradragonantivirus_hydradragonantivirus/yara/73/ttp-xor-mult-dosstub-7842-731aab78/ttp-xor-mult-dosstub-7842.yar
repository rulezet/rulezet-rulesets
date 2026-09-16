rule TTP_XOR_MULT_DOSStub_7842 {
  strings:
    $key_7842 = { 2c 2a [2] 58 32 [2] 1f 30 [2] 58 21 [2] 16 2d [2] 1a 27 [2] 0d 2c [2] 16 62 [2] 2b }

  condition:
    any of them
}