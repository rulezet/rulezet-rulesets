rule TTP_XOR_MULT_DOSStub_2981 {
  strings:
    $key_2981 = { 7d e9 [2] 09 f1 [2] 4e f3 [2] 09 e2 [2] 47 ee [2] 4b e4 [2] 5c ef [2] 47 a1 [2] 7a }

  condition:
    any of them
}