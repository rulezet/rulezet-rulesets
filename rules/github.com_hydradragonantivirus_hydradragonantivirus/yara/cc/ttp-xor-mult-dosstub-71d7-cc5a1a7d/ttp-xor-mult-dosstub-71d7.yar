rule TTP_XOR_MULT_DOSStub_71d7 {
  strings:
    $key_71d7 = { 25 bf [2] 51 a7 [2] 16 a5 [2] 51 b4 [2] 1f b8 [2] 13 b2 [2] 04 b9 [2] 1f f7 [2] 22 }

  condition:
    any of them
}