rule TTP_XOR_MULT_DOSStub_67b9 {
  strings:
    $key_67b9 = { 33 d1 [2] 47 c9 [2] 00 cb [2] 47 da [2] 09 d6 [2] 05 dc [2] 12 d7 [2] 09 99 [2] 34 }

  condition:
    any of them
}