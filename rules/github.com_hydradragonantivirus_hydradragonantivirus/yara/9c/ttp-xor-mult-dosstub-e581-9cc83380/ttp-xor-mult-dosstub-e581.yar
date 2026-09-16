rule TTP_XOR_MULT_DOSStub_e581 {
  strings:
    $key_e581 = { b1 e9 [2] c5 f1 [2] 82 f3 [2] c5 e2 [2] 8b ee [2] 87 e4 [2] 90 ef [2] 8b a1 [2] b6 }

  condition:
    any of them
}