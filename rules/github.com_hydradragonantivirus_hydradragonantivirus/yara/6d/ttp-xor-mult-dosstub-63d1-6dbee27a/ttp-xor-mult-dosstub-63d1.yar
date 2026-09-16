rule TTP_XOR_MULT_DOSStub_63d1 {
  strings:
    $key_63d1 = { 37 b9 [2] 43 a1 [2] 04 a3 [2] 43 b2 [2] 0d be [2] 01 b4 [2] 16 bf [2] 0d f1 [2] 30 }

  condition:
    any of them
}