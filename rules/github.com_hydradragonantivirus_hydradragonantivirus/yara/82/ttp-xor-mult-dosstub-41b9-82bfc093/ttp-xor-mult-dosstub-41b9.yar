rule TTP_XOR_MULT_DOSStub_41b9 {
  strings:
    $key_41b9 = { 15 d1 [2] 61 c9 [2] 26 cb [2] 61 da [2] 2f d6 [2] 23 dc [2] 34 d7 [2] 2f 99 [2] 12 }

  condition:
    any of them
}