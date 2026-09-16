rule TTP_XOR_MULT_DOSStub_a5bb {
  strings:
    $key_a5bb = { f1 d3 [2] 85 cb [2] c2 c9 [2] 85 d8 [2] cb d4 [2] c7 de [2] d0 d5 [2] cb 9b [2] f6 }

  condition:
    any of them
}