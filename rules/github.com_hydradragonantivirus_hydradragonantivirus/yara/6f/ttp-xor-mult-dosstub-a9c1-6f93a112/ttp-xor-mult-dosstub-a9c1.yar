rule TTP_XOR_MULT_DOSStub_a9c1 {
  strings:
    $key_a9c1 = { fd a9 [2] 89 b1 [2] ce b3 [2] 89 a2 [2] c7 ae [2] cb a4 [2] dc af [2] c7 e1 [2] fa }

  condition:
    any of them
}