rule TTP_XOR_MULT_DOSStub_07d7 {
  strings:
    $key_07d7 = { 53 bf [2] 27 a7 [2] 60 a5 [2] 27 b4 [2] 69 b8 [2] 65 b2 [2] 72 b9 [2] 69 f7 [2] 54 }

  condition:
    any of them
}