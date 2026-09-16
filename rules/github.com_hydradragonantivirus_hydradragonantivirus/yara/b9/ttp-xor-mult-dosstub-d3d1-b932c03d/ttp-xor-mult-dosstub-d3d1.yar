rule TTP_XOR_MULT_DOSStub_d3d1 {
  strings:
    $key_d3d1 = { 87 b9 [2] f3 a1 [2] b4 a3 [2] f3 b2 [2] bd be [2] b1 b4 [2] a6 bf [2] bd f1 [2] 80 }

  condition:
    any of them
}