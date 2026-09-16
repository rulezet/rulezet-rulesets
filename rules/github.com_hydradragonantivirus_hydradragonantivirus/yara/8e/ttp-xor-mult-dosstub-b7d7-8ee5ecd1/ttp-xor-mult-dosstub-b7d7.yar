rule TTP_XOR_MULT_DOSStub_b7d7 {
  strings:
    $key_b7d7 = { e3 bf [2] 97 a7 [2] d0 a5 [2] 97 b4 [2] d9 b8 [2] d5 b2 [2] c2 b9 [2] d9 f7 [2] e4 }

  condition:
    any of them
}