rule TTP_XOR_MULT_DOSStub_e4d7 {
  strings:
    $key_e4d7 = { b0 bf [2] c4 a7 [2] 83 a5 [2] c4 b4 [2] 8a b8 [2] 86 b2 [2] 91 b9 [2] 8a f7 [2] b7 }

  condition:
    any of them
}