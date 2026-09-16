rule TTP_XOR_MULT_DOSStub_c7c8 {
  strings:
    $key_c7c8 = { 93 a0 [2] e7 b8 [2] a0 ba [2] e7 ab [2] a9 a7 [2] a5 ad [2] b2 a6 [2] a9 e8 [2] 94 }

  condition:
    any of them
}