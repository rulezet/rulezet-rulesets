rule TTP_XOR_MULT_DOSStub_29d6 {
  strings:
    $key_29d6 = { 7d be [2] 09 a6 [2] 4e a4 [2] 09 b5 [2] 47 b9 [2] 4b b3 [2] 5c b8 [2] 47 f6 [2] 7a }

  condition:
    any of them
}