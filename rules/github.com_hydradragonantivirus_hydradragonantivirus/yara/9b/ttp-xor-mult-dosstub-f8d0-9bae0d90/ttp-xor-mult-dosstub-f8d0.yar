rule TTP_XOR_MULT_DOSStub_f8d0 {
  strings:
    $key_f8d0 = { ac b8 [2] d8 a0 [2] 9f a2 [2] d8 b3 [2] 96 bf [2] 9a b5 [2] 8d be [2] 96 f0 [2] ab }

  condition:
    any of them
}