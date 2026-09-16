rule TTP_XOR_MULT_DOSStub_79d6 {
  strings:
    $key_79d6 = { 2d be [2] 59 a6 [2] 1e a4 [2] 59 b5 [2] 17 b9 [2] 1b b3 [2] 0c b8 [2] 17 f6 [2] 2a }

  condition:
    any of them
}