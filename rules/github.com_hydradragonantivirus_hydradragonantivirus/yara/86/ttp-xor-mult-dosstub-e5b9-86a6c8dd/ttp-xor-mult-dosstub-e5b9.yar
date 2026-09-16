rule TTP_XOR_MULT_DOSStub_e5b9 {
  strings:
    $key_e5b9 = { b1 d1 [2] c5 c9 [2] 82 cb [2] c5 da [2] 8b d6 [2] 87 dc [2] 90 d7 [2] 8b 99 [2] b6 }

  condition:
    any of them
}