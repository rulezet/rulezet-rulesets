rule TTP_XOR_MULT_DOSStub_46d7 {
  strings:
    $key_46d7 = { 12 bf [2] 66 a7 [2] 21 a5 [2] 66 b4 [2] 28 b8 [2] 24 b2 [2] 33 b9 [2] 28 f7 [2] 15 }

  condition:
    any of them
}