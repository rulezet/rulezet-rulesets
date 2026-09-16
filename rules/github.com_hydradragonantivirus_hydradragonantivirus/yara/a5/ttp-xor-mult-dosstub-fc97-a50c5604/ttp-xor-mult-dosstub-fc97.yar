rule TTP_XOR_MULT_DOSStub_fc97 {
  strings:
    $key_fc97 = { a8 ff [2] dc e7 [2] 9b e5 [2] dc f4 [2] 92 f8 [2] 9e f2 [2] 89 f9 [2] 92 b7 [2] af }

  condition:
    any of them
}