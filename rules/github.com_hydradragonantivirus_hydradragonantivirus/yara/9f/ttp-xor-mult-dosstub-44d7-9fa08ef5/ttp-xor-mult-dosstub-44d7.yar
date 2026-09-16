rule TTP_XOR_MULT_DOSStub_44d7 {
  strings:
    $key_44d7 = { 10 bf [2] 64 a7 [2] 23 a5 [2] 64 b4 [2] 2a b8 [2] 26 b2 [2] 31 b9 [2] 2a f7 [2] 17 }

  condition:
    any of them
}