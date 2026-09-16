rule TTP_XOR_MULT_DOSStub_c6d1 {
  strings:
    $key_c6d1 = { 92 b9 [2] e6 a1 [2] a1 a3 [2] e6 b2 [2] a8 be [2] a4 b4 [2] b3 bf [2] a8 f1 [2] 95 }

  condition:
    any of them
}