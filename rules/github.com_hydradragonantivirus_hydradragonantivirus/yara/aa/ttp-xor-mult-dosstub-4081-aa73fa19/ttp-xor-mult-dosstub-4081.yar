rule TTP_XOR_MULT_DOSStub_4081 {
  strings:
    $key_4081 = { 14 e9 [2] 60 f1 [2] 27 f3 [2] 60 e2 [2] 2e ee [2] 22 e4 [2] 35 ef [2] 2e a1 [2] 13 }

  condition:
    any of them
}