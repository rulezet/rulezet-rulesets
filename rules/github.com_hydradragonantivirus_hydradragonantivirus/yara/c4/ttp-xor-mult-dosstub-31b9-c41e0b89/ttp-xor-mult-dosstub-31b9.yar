rule TTP_XOR_MULT_DOSStub_31b9 {
  strings:
    $key_31b9 = { 65 d1 [2] 11 c9 [2] 56 cb [2] 11 da [2] 5f d6 [2] 53 dc [2] 44 d7 [2] 5f 99 [2] 62 }

  condition:
    any of them
}