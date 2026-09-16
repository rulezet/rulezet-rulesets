rule TTP_XOR_MULT_DOSStub_54b9 {
  strings:
    $key_54b9 = { 00 d1 [2] 74 c9 [2] 33 cb [2] 74 da [2] 3a d6 [2] 36 dc [2] 21 d7 [2] 3a 99 [2] 07 }

  condition:
    any of them
}