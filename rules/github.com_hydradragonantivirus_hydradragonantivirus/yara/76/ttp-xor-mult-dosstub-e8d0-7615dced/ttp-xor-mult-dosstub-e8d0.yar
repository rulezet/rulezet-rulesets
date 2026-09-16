rule TTP_XOR_MULT_DOSStub_e8d0 {
  strings:
    $key_e8d0 = { bc b8 [2] c8 a0 [2] 8f a2 [2] c8 b3 [2] 86 bf [2] 8a b5 [2] 9d be [2] 86 f0 [2] bb }

  condition:
    any of them
}