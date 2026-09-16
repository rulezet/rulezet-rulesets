rule TTP_XOR_MULT_DOSStub_0581 {
  strings:
    $key_0581 = { 51 e9 [2] 25 f1 [2] 62 f3 [2] 25 e2 [2] 6b ee [2] 67 e4 [2] 70 ef [2] 6b a1 [2] 56 }

  condition:
    any of them
}