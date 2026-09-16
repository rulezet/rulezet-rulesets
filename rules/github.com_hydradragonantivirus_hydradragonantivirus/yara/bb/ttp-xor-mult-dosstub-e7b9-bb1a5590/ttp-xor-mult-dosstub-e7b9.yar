rule TTP_XOR_MULT_DOSStub_e7b9 {
  strings:
    $key_e7b9 = { b3 d1 [2] c7 c9 [2] 80 cb [2] c7 da [2] 89 d6 [2] 85 dc [2] 92 d7 [2] 89 99 [2] b4 }

  condition:
    any of them
}