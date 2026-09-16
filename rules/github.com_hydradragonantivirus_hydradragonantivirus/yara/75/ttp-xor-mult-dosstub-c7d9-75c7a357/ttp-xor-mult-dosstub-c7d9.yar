rule TTP_XOR_MULT_DOSStub_c7d9 {
  strings:
    $key_c7d9 = { 93 b1 [2] e7 a9 [2] a0 ab [2] e7 ba [2] a9 b6 [2] a5 bc [2] b2 b7 [2] a9 f9 [2] 94 }

  condition:
    any of them
}