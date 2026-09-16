rule TTP_XOR_MULT_DOSStub_b1b2 {
  strings:
    $key_b1b2 = { e5 da [2] 91 c2 [2] d6 c0 [2] 91 d1 [2] df dd [2] d3 d7 [2] c4 dc [2] df 92 [2] e2 }

  condition:
    any of them
}