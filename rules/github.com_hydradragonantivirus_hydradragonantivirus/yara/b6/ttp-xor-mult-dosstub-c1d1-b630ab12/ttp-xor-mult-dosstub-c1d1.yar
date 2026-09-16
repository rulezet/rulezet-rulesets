rule TTP_XOR_MULT_DOSStub_c1d1 {
  strings:
    $key_c1d1 = { 95 b9 [2] e1 a1 [2] a6 a3 [2] e1 b2 [2] af be [2] a3 b4 [2] b4 bf [2] af f1 [2] 92 }

  condition:
    any of them
}