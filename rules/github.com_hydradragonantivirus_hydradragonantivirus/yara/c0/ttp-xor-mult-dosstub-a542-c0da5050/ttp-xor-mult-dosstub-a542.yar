rule TTP_XOR_MULT_DOSStub_a542 {
  strings:
    $key_a542 = { f1 2a [2] 85 32 [2] c2 30 [2] 85 21 [2] cb 2d [2] c7 27 [2] d0 2c [2] cb 62 [2] f6 }

  condition:
    any of them
}