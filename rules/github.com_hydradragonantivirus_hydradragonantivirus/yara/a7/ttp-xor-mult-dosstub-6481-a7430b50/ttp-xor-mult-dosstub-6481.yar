rule TTP_XOR_MULT_DOSStub_6481 {
  strings:
    $key_6481 = { 30 e9 [2] 44 f1 [2] 03 f3 [2] 44 e2 [2] 0a ee [2] 06 e4 [2] 11 ef [2] 0a a1 [2] 37 }

  condition:
    any of them
}