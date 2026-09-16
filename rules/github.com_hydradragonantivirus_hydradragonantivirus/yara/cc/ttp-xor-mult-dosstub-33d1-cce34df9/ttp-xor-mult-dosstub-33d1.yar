rule TTP_XOR_MULT_DOSStub_33d1 {
  strings:
    $key_33d1 = { 67 b9 [2] 13 a1 [2] 54 a3 [2] 13 b2 [2] 5d be [2] 51 b4 [2] 46 bf [2] 5d f1 [2] 60 }

  condition:
    any of them
}