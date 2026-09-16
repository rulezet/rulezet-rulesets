rule TTP_XOR_MULT_DOSStub_ebbc {
  strings:
    $key_ebbc = { bf d4 [2] cb cc [2] 8c ce [2] cb df [2] 85 d3 [2] 89 d9 [2] 9e d2 [2] 85 9c [2] b8 }

  condition:
    any of them
}