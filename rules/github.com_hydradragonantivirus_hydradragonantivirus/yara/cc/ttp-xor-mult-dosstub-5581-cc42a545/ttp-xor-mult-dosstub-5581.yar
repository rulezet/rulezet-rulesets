rule TTP_XOR_MULT_DOSStub_5581 {
  strings:
    $key_5581 = { 01 e9 [2] 75 f1 [2] 32 f3 [2] 75 e2 [2] 3b ee [2] 37 e4 [2] 20 ef [2] 3b a1 [2] 06 }

  condition:
    any of them
}