rule TTP_XOR_MULT_DOSStub_a5b6 {
  strings:
    $key_a5b6 = { f1 de [2] 85 c6 [2] c2 c4 [2] 85 d5 [2] cb d9 [2] c7 d3 [2] d0 d8 [2] cb 96 [2] f6 }

  condition:
    any of them
}