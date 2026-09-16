rule TTP_XOR_MULT_DOSStub_c6b2 {
  strings:
    $key_c6b2 = { 92 da [2] e6 c2 [2] a1 c0 [2] e6 d1 [2] a8 dd [2] a4 d7 [2] b3 dc [2] a8 92 [2] 95 }

  condition:
    any of them
}