rule TTP_XOR_MULT_DOSStub_1481 {
  strings:
    $key_1481 = { 40 e9 [2] 34 f1 [2] 73 f3 [2] 34 e2 [2] 7a ee [2] 76 e4 [2] 61 ef [2] 7a a1 [2] 47 }

  condition:
    any of them
}