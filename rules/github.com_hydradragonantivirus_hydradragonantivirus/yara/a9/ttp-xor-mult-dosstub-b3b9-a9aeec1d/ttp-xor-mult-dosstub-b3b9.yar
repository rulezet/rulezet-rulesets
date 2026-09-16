rule TTP_XOR_MULT_DOSStub_b3b9 {
  strings:
    $key_b3b9 = { e7 d1 [2] 93 c9 [2] d4 cb [2] 93 da [2] dd d6 [2] d1 dc [2] c6 d7 [2] dd 99 [2] e0 }

  condition:
    any of them
}