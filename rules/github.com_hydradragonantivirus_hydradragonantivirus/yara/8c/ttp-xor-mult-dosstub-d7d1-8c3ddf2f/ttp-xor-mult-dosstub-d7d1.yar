rule TTP_XOR_MULT_DOSStub_d7d1 {
  strings:
    $key_d7d1 = { 83 b9 [2] f7 a1 [2] b0 a3 [2] f7 b2 [2] b9 be [2] b5 b4 [2] a2 bf [2] b9 f1 [2] 84 }

  condition:
    any of them
}