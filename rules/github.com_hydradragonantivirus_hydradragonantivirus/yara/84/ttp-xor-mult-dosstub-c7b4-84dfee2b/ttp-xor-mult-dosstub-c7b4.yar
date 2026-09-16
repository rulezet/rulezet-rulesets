rule TTP_XOR_MULT_DOSStub_c7b4 {
  strings:
    $key_c7b4 = { 93 dc [2] e7 c4 [2] a0 c6 [2] e7 d7 [2] a9 db [2] a5 d1 [2] b2 da [2] a9 94 [2] 94 }

  condition:
    any of them
}