rule TTP_XOR_MULT_DOSStub_00b9 {
  strings:
    $key_00b9 = { 54 d1 [2] 20 c9 [2] 67 cb [2] 20 da [2] 6e d6 [2] 62 dc [2] 75 d7 [2] 6e 99 [2] 53 }

  condition:
    any of them
}