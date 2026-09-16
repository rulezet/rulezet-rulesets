rule TTP_XOR_MULT_DOSStub_0981 {
  strings:
    $key_0981 = { 5d e9 [2] 29 f1 [2] 6e f3 [2] 29 e2 [2] 67 ee [2] 6b e4 [2] 7c ef [2] 67 a1 [2] 5a }

  condition:
    any of them
}