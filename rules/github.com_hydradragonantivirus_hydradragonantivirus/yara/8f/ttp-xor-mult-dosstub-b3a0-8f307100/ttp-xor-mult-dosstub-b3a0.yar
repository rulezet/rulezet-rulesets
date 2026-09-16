rule TTP_XOR_MULT_DOSStub_b3a0 {
  strings:
    $key_b3a0 = { e7 c8 [2] 93 d0 [2] d4 d2 [2] 93 c3 [2] dd cf [2] d1 c5 [2] c6 ce [2] dd 80 [2] e0 }

  condition:
    any of them
}