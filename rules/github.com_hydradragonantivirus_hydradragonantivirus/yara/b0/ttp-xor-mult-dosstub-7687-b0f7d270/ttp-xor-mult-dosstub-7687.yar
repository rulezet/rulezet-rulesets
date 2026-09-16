rule TTP_XOR_MULT_DOSStub_7687 {
  strings:
    $key_7687 = { 22 ef [2] 56 f7 [2] 11 f5 [2] 56 e4 [2] 18 e8 [2] 14 e2 [2] 03 e9 [2] 18 a7 [2] 25 }

  condition:
    any of them
}