rule TTP_XOR_MULT_DOSStub_1581 {
  strings:
    $key_1581 = { 41 e9 [2] 35 f1 [2] 72 f3 [2] 35 e2 [2] 7b ee [2] 77 e4 [2] 60 ef [2] 7b a1 [2] 46 }

  condition:
    any of them
}