rule TTP_XOR_MULT_DOSStub_fcd1 {
  strings:
    $key_fcd1 = { a8 b9 [2] dc a1 [2] 9b a3 [2] dc b2 [2] 92 be [2] 9e b4 [2] 89 bf [2] 92 f1 [2] af }

  condition:
    any of them
}