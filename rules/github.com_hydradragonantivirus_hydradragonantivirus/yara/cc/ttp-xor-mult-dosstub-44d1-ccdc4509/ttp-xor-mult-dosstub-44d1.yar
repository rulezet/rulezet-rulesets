rule TTP_XOR_MULT_DOSStub_44d1 {
  strings:
    $key_44d1 = { 10 b9 [2] 64 a1 [2] 23 a3 [2] 64 b2 [2] 2a be [2] 26 b4 [2] 31 bf [2] 2a f1 [2] 17 }

  condition:
    any of them
}