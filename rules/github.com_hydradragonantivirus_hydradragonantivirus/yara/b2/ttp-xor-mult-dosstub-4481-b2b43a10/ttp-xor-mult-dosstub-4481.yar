rule TTP_XOR_MULT_DOSStub_4481 {
  strings:
    $key_4481 = { 10 e9 [2] 64 f1 [2] 23 f3 [2] 64 e2 [2] 2a ee [2] 26 e4 [2] 31 ef [2] 2a a1 [2] 17 }

  condition:
    any of them
}