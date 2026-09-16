rule TTP_XOR_MULT_DOSStub_50b9 {
  strings:
    $key_50b9 = { 04 d1 [2] 70 c9 [2] 37 cb [2] 70 da [2] 3e d6 [2] 32 dc [2] 25 d7 [2] 3e 99 [2] 03 }

  condition:
    any of them
}