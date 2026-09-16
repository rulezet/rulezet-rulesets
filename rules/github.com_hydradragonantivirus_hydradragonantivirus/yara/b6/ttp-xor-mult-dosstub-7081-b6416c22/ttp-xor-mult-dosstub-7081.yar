rule TTP_XOR_MULT_DOSStub_7081 {
  strings:
    $key_7081 = { 24 e9 [2] 50 f1 [2] 17 f3 [2] 50 e2 [2] 1e ee [2] 12 e4 [2] 05 ef [2] 1e a1 [2] 23 }

  condition:
    any of them
}