rule TTP_XOR_MULT_DOSStub_ddd1 {
  strings:
    $key_ddd1 = { 89 b9 [2] fd a1 [2] ba a3 [2] fd b2 [2] b3 be [2] bf b4 [2] a8 bf [2] b3 f1 [2] 8e }

  condition:
    any of them
}