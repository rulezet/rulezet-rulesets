rule TTP_XOR_MULT_DOSStub_f581 {
  strings:
    $key_f581 = { a1 e9 [2] d5 f1 [2] 92 f3 [2] d5 e2 [2] 9b ee [2] 97 e4 [2] 80 ef [2] 9b a1 [2] a6 }

  condition:
    any of them
}