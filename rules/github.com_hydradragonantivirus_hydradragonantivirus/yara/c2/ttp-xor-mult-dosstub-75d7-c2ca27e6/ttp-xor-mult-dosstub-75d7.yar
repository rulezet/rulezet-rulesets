rule TTP_XOR_MULT_DOSStub_75d7 {
  strings:
    $key_75d7 = { 21 bf [2] 55 a7 [2] 12 a5 [2] 55 b4 [2] 1b b8 [2] 17 b2 [2] 00 b9 [2] 1b f7 [2] 26 }

  condition:
    any of them
}