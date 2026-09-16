rule TTP_XOR_MULT_DOSStub_0487 {
  strings:
    $key_0487 = { 50 ef [2] 24 f7 [2] 63 f5 [2] 24 e4 [2] 6a e8 [2] 66 e2 [2] 71 e9 [2] 6a a7 [2] 57 }

  condition:
    any of them
}