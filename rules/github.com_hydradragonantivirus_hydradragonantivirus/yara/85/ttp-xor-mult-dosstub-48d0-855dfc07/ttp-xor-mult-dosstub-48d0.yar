rule TTP_XOR_MULT_DOSStub_48d0 {
  strings:
    $key_48d0 = { 1c b8 [2] 68 a0 [2] 2f a2 [2] 68 b3 [2] 26 bf [2] 2a b5 [2] 3d be [2] 26 f0 [2] 1b }

  condition:
    any of them
}