rule TTP_XOR_MULT_DOSStub_c3d1 {
  strings:
    $key_c3d1 = { 97 b9 [2] e3 a1 [2] a4 a3 [2] e3 b2 [2] ad be [2] a1 b4 [2] b6 bf [2] ad f1 [2] 90 }

  condition:
    any of them
}