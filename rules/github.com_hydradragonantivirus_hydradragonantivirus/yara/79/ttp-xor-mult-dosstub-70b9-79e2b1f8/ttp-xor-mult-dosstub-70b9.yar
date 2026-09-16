rule TTP_XOR_MULT_DOSStub_70b9 {
  strings:
    $key_70b9 = { 24 d1 [2] 50 c9 [2] 17 cb [2] 50 da [2] 1e d6 [2] 12 dc [2] 05 d7 [2] 1e 99 [2] 23 }

  condition:
    any of them
}