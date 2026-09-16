rule TTP_XOR_MULT_DOSStub_ebb6 {
  strings:
    $key_ebb6 = { bf de [2] cb c6 [2] 8c c4 [2] cb d5 [2] 85 d9 [2] 89 d3 [2] 9e d8 [2] 85 96 [2] b8 }

  condition:
    any of them
}