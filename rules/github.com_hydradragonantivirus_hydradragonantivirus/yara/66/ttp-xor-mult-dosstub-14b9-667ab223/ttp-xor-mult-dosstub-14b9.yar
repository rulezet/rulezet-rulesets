rule TTP_XOR_MULT_DOSStub_14b9 {
  strings:
    $key_14b9 = { 40 d1 [2] 34 c9 [2] 73 cb [2] 34 da [2] 7a d6 [2] 76 dc [2] 61 d7 [2] 7a 99 [2] 47 }

  condition:
    any of them
}