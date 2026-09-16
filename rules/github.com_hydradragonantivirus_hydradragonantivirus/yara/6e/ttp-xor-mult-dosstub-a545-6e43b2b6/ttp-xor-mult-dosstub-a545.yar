rule TTP_XOR_MULT_DOSStub_a545 {
  strings:
    $key_a545 = { f1 2d [2] 85 35 [2] c2 37 [2] 85 26 [2] cb 2a [2] c7 20 [2] d0 2b [2] cb 65 [2] f6 }

  condition:
    any of them
}