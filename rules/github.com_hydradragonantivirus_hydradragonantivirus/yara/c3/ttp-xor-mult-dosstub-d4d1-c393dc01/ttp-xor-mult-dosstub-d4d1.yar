rule TTP_XOR_MULT_DOSStub_d4d1 {
  strings:
    $key_d4d1 = { 80 b9 [2] f4 a1 [2] b3 a3 [2] f4 b2 [2] ba be [2] b6 b4 [2] a1 bf [2] ba f1 [2] 87 }

  condition:
    any of them
}