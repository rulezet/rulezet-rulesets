rule TTP_XOR_MULT_DOSStub_e5d7 {
  strings:
    $key_e5d7 = { b1 bf [2] c5 a7 [2] 82 a5 [2] c5 b4 [2] 8b b8 [2] 87 b2 [2] 90 b9 [2] 8b f7 [2] b6 }

  condition:
    any of them
}