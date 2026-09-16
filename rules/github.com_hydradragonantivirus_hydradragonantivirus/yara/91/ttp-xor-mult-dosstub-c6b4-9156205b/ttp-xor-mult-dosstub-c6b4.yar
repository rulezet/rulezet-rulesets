rule TTP_XOR_MULT_DOSStub_c6b4 {
  strings:
    $key_c6b4 = { 92 dc [2] e6 c4 [2] a1 c6 [2] e6 d7 [2] a8 db [2] a4 d1 [2] b3 da [2] a8 94 [2] 95 }

  condition:
    any of them
}