rule TTP_XOR_MULT_DOSStub_13d1 {
  strings:
    $key_13d1 = { 47 b9 [2] 33 a1 [2] 74 a3 [2] 33 b2 [2] 7d be [2] 71 b4 [2] 66 bf [2] 7d f1 [2] 40 }

  condition:
    any of them
}