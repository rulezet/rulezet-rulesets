rule TTP_XOR_MULT_DOSStub_b4b2 {
  strings:
    $key_b4b2 = { e0 da [2] 94 c2 [2] d3 c0 [2] 94 d1 [2] da dd [2] d6 d7 [2] c1 dc [2] da 92 [2] e7 }

  condition:
    any of them
}