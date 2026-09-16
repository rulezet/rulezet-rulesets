rule TTP_XOR_MULT_DOSStub_60b9 {
  strings:
    $key_60b9 = { 34 d1 [2] 40 c9 [2] 07 cb [2] 40 da [2] 0e d6 [2] 02 dc [2] 15 d7 [2] 0e 99 [2] 33 }

  condition:
    any of them
}