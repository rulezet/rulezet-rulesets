rule TTP_XOR_MULT_DOSStub_c1d0 {
  strings:
    $key_c1d0 = { 95 b8 [2] e1 a0 [2] a6 a2 [2] e1 b3 [2] af bf [2] a3 b5 [2] b4 be [2] af f0 [2] 92 }

  condition:
    any of them
}