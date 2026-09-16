rule TTP_XOR_MULT_DOSStub_1181 {
  strings:
    $key_1181 = { 45 e9 [2] 31 f1 [2] 76 f3 [2] 31 e2 [2] 7f ee [2] 73 e4 [2] 64 ef [2] 7f a1 [2] 42 }

  condition:
    any of them
}