rule TTP_XOR_MULT_DOSStub_a576 {
  strings:
    $key_a576 = { f1 1e [2] 85 06 [2] c2 04 [2] 85 15 [2] cb 19 [2] c7 13 [2] d0 18 [2] cb 56 [2] f6 }

  condition:
    any of them
}