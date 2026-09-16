rule TTP_XOR_MULT_DOSStub_19d6 {
  strings:
    $key_19d6 = { 4d be [2] 39 a6 [2] 7e a4 [2] 39 b5 [2] 77 b9 [2] 7b b3 [2] 6c b8 [2] 77 f6 [2] 4a }

  condition:
    any of them
}