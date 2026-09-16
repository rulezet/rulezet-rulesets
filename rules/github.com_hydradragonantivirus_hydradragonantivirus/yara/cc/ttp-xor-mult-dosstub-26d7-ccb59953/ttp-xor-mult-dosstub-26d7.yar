rule TTP_XOR_MULT_DOSStub_26d7 {
  strings:
    $key_26d7 = { 72 bf [2] 06 a7 [2] 41 a5 [2] 06 b4 [2] 48 b8 [2] 44 b2 [2] 53 b9 [2] 48 f7 [2] 75 }

  condition:
    any of them
}