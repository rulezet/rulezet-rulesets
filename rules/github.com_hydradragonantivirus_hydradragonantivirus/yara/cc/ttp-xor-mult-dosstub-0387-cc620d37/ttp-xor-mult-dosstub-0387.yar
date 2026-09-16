rule TTP_XOR_MULT_DOSStub_0387 {
  strings:
    $key_0387 = { 57 ef [2] 23 f7 [2] 64 f5 [2] 23 e4 [2] 6d e8 [2] 61 e2 [2] 76 e9 [2] 6d a7 [2] 50 }

  condition:
    any of them
}