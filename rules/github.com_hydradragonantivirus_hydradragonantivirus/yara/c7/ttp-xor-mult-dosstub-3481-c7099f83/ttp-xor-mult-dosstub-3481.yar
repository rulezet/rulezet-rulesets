rule TTP_XOR_MULT_DOSStub_3481 {
  strings:
    $key_3481 = { 60 e9 [2] 14 f1 [2] 53 f3 [2] 14 e2 [2] 5a ee [2] 56 e4 [2] 41 ef [2] 5a a1 [2] 67 }

  condition:
    any of them
}