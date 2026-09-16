rule TTP_XOR_MULT_DOSStub_d481 {
  strings:
    $key_d481 = { 80 e9 [2] f4 f1 [2] b3 f3 [2] f4 e2 [2] ba ee [2] b6 e4 [2] a1 ef [2] ba a1 [2] 87 }

  condition:
    any of them
}