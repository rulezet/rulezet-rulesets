rule TTP_XOR_MULT_DOSStub_31d7 {
  strings:
    $key_31d7 = { 65 bf [2] 11 a7 [2] 56 a5 [2] 11 b4 [2] 5f b8 [2] 53 b2 [2] 44 b9 [2] 5f f7 [2] 62 }

  condition:
    any of them
}