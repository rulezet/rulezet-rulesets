rule TTP_XOR_MULT_DOSStub_1381 {
  strings:
    $key_1381 = { 47 e9 [2] 33 f1 [2] 74 f3 [2] 33 e2 [2] 7d ee [2] 71 e4 [2] 66 ef [2] 7d a1 [2] 40 }

  condition:
    any of them
}