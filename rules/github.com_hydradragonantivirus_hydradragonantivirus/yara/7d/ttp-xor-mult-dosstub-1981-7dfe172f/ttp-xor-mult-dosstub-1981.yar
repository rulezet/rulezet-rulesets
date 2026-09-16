rule TTP_XOR_MULT_DOSStub_1981 {
  strings:
    $key_1981 = { 4d e9 [2] 39 f1 [2] 7e f3 [2] 39 e2 [2] 77 ee [2] 7b e4 [2] 6c ef [2] 77 a1 [2] 4a }

  condition:
    any of them
}