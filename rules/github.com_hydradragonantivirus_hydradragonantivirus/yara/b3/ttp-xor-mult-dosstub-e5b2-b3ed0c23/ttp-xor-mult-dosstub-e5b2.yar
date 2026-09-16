rule TTP_XOR_MULT_DOSStub_e5b2 {
  strings:
    $key_e5b2 = { b1 da [2] c5 c2 [2] 82 c0 [2] c5 d1 [2] 8b dd [2] 87 d7 [2] 90 dc [2] 8b 92 [2] b6 }

  condition:
    any of them
}