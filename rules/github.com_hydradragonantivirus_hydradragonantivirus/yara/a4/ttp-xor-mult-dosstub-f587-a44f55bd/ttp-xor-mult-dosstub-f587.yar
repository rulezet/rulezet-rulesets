rule TTP_XOR_MULT_DOSStub_f587 {
  strings:
    $key_f587 = { a1 ef [2] d5 f7 [2] 92 f5 [2] d5 e4 [2] 9b e8 [2] 97 e2 [2] 80 e9 [2] 9b a7 [2] a6 }

  condition:
    any of them
}