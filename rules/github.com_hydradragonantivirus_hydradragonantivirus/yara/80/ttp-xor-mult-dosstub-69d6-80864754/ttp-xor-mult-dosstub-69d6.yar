rule TTP_XOR_MULT_DOSStub_69d6 {
  strings:
    $key_69d6 = { 3d be [2] 49 a6 [2] 0e a4 [2] 49 b5 [2] 07 b9 [2] 0b b3 [2] 1c b8 [2] 07 f6 [2] 3a }

  condition:
    any of them
}