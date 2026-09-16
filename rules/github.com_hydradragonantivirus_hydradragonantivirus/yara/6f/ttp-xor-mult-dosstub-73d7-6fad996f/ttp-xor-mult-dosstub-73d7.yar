rule TTP_XOR_MULT_DOSStub_73d7 {
  strings:
    $key_73d7 = { 27 bf [2] 53 a7 [2] 14 a5 [2] 53 b4 [2] 1d b8 [2] 11 b2 [2] 06 b9 [2] 1d f7 [2] 20 }

  condition:
    any of them
}