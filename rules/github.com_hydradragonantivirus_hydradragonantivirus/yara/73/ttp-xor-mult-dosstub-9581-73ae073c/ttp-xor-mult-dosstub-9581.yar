rule TTP_XOR_MULT_DOSStub_9581 {
  strings:
    $key_9581 = { c1 e9 [2] b5 f1 [2] f2 f3 [2] b5 e2 [2] fb ee [2] f7 e4 [2] e0 ef [2] fb a1 [2] c6 }

  condition:
    any of them
}