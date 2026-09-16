rule TTP_XOR_MULT_DOSStub_40b9 {
  strings:
    $key_40b9 = { 14 d1 [2] 60 c9 [2] 27 cb [2] 60 da [2] 2e d6 [2] 22 dc [2] 35 d7 [2] 2e 99 [2] 13 }

  condition:
    any of them
}