rule TTP_XOR_MULT_DOSStub_27b9 {
  strings:
    $key_27b9 = { 73 d1 [2] 07 c9 [2] 40 cb [2] 07 da [2] 49 d6 [2] 45 dc [2] 52 d7 [2] 49 99 [2] 74 }

  condition:
    any of them
}