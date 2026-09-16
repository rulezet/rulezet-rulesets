rule TTP_XOR_MULT_DOSStub_d581 {
  strings:
    $key_d581 = { 81 e9 [2] f5 f1 [2] b2 f3 [2] f5 e2 [2] bb ee [2] b7 e4 [2] a0 ef [2] bb a1 [2] 86 }

  condition:
    any of them
}