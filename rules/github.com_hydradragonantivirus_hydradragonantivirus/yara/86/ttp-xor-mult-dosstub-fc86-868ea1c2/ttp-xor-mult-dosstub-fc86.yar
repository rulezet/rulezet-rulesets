rule TTP_XOR_MULT_DOSStub_fc86 {
  strings:
    $key_fc86 = { a8 ee [2] dc f6 [2] 9b f4 [2] dc e5 [2] 92 e9 [2] 9e e3 [2] 89 e8 [2] 92 a6 [2] af }

  condition:
    any of them
}