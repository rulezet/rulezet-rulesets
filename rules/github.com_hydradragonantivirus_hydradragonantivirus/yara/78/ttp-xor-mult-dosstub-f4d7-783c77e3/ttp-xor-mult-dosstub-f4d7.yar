rule TTP_XOR_MULT_DOSStub_f4d7 {
  strings:
    $key_f4d7 = { a0 bf [2] d4 a7 [2] 93 a5 [2] d4 b4 [2] 9a b8 [2] 96 b2 [2] 81 b9 [2] 9a f7 [2] a7 }

  condition:
    any of them
}