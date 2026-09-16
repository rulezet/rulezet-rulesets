rule TTP_XOR_MULT_DOSStub_30b9 {
  strings:
    $key_30b9 = { 64 d1 [2] 10 c9 [2] 57 cb [2] 10 da [2] 5e d6 [2] 52 dc [2] 45 d7 [2] 5e 99 [2] 63 }

  condition:
    any of them
}