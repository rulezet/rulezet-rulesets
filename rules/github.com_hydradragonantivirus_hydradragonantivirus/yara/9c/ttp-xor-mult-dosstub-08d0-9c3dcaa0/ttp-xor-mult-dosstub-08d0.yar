rule TTP_XOR_MULT_DOSStub_08d0 {
  strings:
    $key_08d0 = { 5c b8 [2] 28 a0 [2] 6f a2 [2] 28 b3 [2] 66 bf [2] 6a b5 [2] 7d be [2] 66 f0 [2] 5b }

  condition:
    any of them
}