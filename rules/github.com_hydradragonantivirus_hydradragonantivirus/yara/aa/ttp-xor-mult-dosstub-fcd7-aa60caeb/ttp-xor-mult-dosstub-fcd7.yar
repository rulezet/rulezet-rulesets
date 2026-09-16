rule TTP_XOR_MULT_DOSStub_fcd7 {
  strings:
    $key_fcd7 = { a8 bf [2] dc a7 [2] 9b a5 [2] dc b4 [2] 92 b8 [2] 9e b2 [2] 89 b9 [2] 92 f7 [2] af }

  condition:
    any of them
}