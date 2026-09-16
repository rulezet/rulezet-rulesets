rule TTP_XOR_MULT_DOSStub_e587 {
  strings:
    $key_e587 = { b1 ef [2] c5 f7 [2] 82 f5 [2] c5 e4 [2] 8b e8 [2] 87 e2 [2] 90 e9 [2] 8b a7 [2] b6 }

  condition:
    any of them
}