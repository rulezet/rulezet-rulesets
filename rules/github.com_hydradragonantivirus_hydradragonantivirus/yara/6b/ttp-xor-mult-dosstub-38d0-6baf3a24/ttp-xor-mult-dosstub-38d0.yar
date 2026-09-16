rule TTP_XOR_MULT_DOSStub_38d0 {
  strings:
    $key_38d0 = { 6c b8 [2] 18 a0 [2] 5f a2 [2] 18 b3 [2] 56 bf [2] 5a b5 [2] 4d be [2] 56 f0 [2] 6b }

  condition:
    any of them
}