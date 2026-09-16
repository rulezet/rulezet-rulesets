rule TTP_XOR_MULT_DOSStub_21d7 {
  strings:
    $key_21d7 = { 75 bf [2] 01 a7 [2] 46 a5 [2] 01 b4 [2] 4f b8 [2] 43 b2 [2] 54 b9 [2] 4f f7 [2] 72 }

  condition:
    any of them
}