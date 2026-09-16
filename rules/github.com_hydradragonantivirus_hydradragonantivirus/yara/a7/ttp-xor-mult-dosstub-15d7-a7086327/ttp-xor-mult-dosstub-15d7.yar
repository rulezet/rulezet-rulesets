rule TTP_XOR_MULT_DOSStub_15d7 {
  strings:
    $key_15d7 = { 41 bf [2] 35 a7 [2] 72 a5 [2] 35 b4 [2] 7b b8 [2] 77 b2 [2] 60 b9 [2] 7b f7 [2] 46 }

  condition:
    any of them
}