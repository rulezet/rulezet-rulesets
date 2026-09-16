rule TTP_XOR_MULT_DOSStub_d6d7 {
  strings:
    $key_d6d7 = { 82 bf [2] f6 a7 [2] b1 a5 [2] f6 b4 [2] b8 b8 [2] b4 b2 [2] a3 b9 [2] b8 f7 [2] 85 }

  condition:
    any of them
}