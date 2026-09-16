rule TTP_XOR_MULT_DOSStub_d6d0 {
  strings:
    $key_d6d0 = { 82 b8 [2] f6 a0 [2] b1 a2 [2] f6 b3 [2] b8 bf [2] b4 b5 [2] a3 be [2] b8 f0 [2] 85 }

  condition:
    any of them
}