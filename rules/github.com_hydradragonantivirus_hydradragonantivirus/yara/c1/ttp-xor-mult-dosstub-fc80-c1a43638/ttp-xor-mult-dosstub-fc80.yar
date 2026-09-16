rule TTP_XOR_MULT_DOSStub_fc80 {
  strings:
    $key_fc80 = { a8 e8 [2] dc f0 [2] 9b f2 [2] dc e3 [2] 92 ef [2] 9e e5 [2] 89 ee [2] 92 a0 [2] af }

  condition:
    any of them
}