rule TTP_XOR_MULT_DOSStub_1681 {
  strings:
    $key_1681 = { 42 e9 [2] 36 f1 [2] 71 f3 [2] 36 e2 [2] 78 ee [2] 74 e4 [2] 63 ef [2] 78 a1 [2] 45 }

  condition:
    any of them
}