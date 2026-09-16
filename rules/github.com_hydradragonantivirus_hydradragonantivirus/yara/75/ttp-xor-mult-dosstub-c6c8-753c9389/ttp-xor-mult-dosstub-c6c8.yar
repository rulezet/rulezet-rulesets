rule TTP_XOR_MULT_DOSStub_c6c8 {
  strings:
    $key_c6c8 = { 92 a0 [2] e6 b8 [2] a1 ba [2] e6 ab [2] a8 a7 [2] a4 ad [2] b3 a6 [2] a8 e8 [2] 95 }

  condition:
    any of them
}