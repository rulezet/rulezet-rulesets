rule TTP_XOR_MULT_DOSStub_25d7 {
  strings:
    $key_25d7 = { 71 bf [2] 05 a7 [2] 42 a5 [2] 05 b4 [2] 4b b8 [2] 47 b2 [2] 50 b9 [2] 4b f7 [2] 76 }

  condition:
    any of them
}