rule TTP_XOR_MULT_DOSStub_d1d1 {
  strings:
    $key_d1d1 = { 85 b9 [2] f1 a1 [2] b6 a3 [2] f1 b2 [2] bf be [2] b3 b4 [2] a4 bf [2] bf f1 [2] 82 }

  condition:
    any of them
}