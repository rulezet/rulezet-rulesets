rule TTP_XOR_MULT_DOSStub_c7d1 {
  strings:
    $key_c7d1 = { 93 b9 [2] e7 a1 [2] a0 a3 [2] e7 b2 [2] a9 be [2] a5 b4 [2] b2 bf [2] a9 f1 [2] 94 }

  condition:
    any of them
}