rule TTP_XOR_MULT_DOSStub_fcd6 {
  strings:
    $key_fcd6 = { a8 be [2] dc a6 [2] 9b a4 [2] dc b5 [2] 92 b9 [2] 9e b3 [2] 89 b8 [2] 92 f6 [2] af }

  condition:
    any of them
}