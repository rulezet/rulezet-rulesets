rule TTP_XOR_MULT_DOSStub_a1b2 {
  strings:
    $key_a1b2 = { f5 da [2] 81 c2 [2] c6 c0 [2] 81 d1 [2] cf dd [2] c3 d7 [2] d4 dc [2] cf 92 [2] f2 }

  condition:
    any of them
}