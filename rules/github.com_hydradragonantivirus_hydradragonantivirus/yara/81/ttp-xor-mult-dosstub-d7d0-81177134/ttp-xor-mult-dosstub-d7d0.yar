rule TTP_XOR_MULT_DOSStub_d7d0 {
  strings:
    $key_d7d0 = { 83 b8 [2] f7 a0 [2] b0 a2 [2] f7 b3 [2] b9 bf [2] b5 b5 [2] a2 be [2] b9 f0 [2] 84 }

  condition:
    any of them
}