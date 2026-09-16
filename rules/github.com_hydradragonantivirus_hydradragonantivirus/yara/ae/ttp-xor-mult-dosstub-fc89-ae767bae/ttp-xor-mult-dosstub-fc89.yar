rule TTP_XOR_MULT_DOSStub_fc89 {
  strings:
    $key_fc89 = { a8 e1 [2] dc f9 [2] 9b fb [2] dc ea [2] 92 e6 [2] 9e ec [2] 89 e7 [2] 92 a9 [2] af }

  condition:
    any of them
}