rule TTP_XOR_MULT_DOSStub_fc81 {
  strings:
    $key_fc81 = { a8 e9 [2] dc f1 [2] 9b f3 [2] dc e2 [2] 92 ee [2] 9e e4 [2] 89 ef [2] 92 a1 [2] af }

  condition:
    any of them
}