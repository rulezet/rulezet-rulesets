rule TTP_XOR_MULT_DOSStub_09d6 {
  strings:
    $key_09d6 = { 5d be [2] 29 a6 [2] 6e a4 [2] 29 b5 [2] 67 b9 [2] 6b b3 [2] 7c b8 [2] 67 f6 [2] 5a }

  condition:
    any of them
}