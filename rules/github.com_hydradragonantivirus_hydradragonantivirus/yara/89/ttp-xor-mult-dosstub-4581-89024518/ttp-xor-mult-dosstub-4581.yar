rule TTP_XOR_MULT_DOSStub_4581 {
  strings:
    $key_4581 = { 11 e9 [2] 65 f1 [2] 22 f3 [2] 65 e2 [2] 2b ee [2] 27 e4 [2] 30 ef [2] 2b a1 [2] 16 }

  condition:
    any of them
}