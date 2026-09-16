rule TTP_XOR_MULT_DOSStub_fc87 {
  strings:
    $key_fc87 = { a8 ef [2] dc f7 [2] 9b f5 [2] dc e4 [2] 92 e8 [2] 9e e2 [2] 89 e9 [2] 92 a7 [2] af }

  condition:
    any of them
}