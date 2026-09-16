rule TTP_XOR_MULT_DOSStub_c187 {
  strings:
    $key_c187 = { 95 ef [2] e1 f7 [2] a6 f5 [2] e1 e4 [2] af e8 [2] a3 e2 [2] b4 e9 [2] af a7 [2] 92 }

  condition:
    any of them
}