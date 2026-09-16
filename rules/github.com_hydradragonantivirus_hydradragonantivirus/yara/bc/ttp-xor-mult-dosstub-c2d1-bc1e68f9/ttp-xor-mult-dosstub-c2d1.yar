rule TTP_XOR_MULT_DOSStub_c2d1 {
  strings:
    $key_c2d1 = { 96 b9 [2] e2 a1 [2] a5 a3 [2] e2 b2 [2] ac be [2] a0 b4 [2] b7 bf [2] ac f1 [2] 91 }

  condition:
    any of them
}