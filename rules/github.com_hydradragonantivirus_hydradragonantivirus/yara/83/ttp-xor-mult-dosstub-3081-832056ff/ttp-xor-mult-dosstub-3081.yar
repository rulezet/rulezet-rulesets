rule TTP_XOR_MULT_DOSStub_3081 {
  strings:
    $key_3081 = { 64 e9 [2] 10 f1 [2] 57 f3 [2] 10 e2 [2] 5e ee [2] 52 e4 [2] 45 ef [2] 5e a1 [2] 63 }

  condition:
    any of them
}