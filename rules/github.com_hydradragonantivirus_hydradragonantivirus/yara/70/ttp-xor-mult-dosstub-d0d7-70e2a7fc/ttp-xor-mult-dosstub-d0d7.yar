rule TTP_XOR_MULT_DOSStub_d0d7 {
  strings:
    $key_d0d7 = { 84 bf [2] f0 a7 [2] b7 a5 [2] f0 b4 [2] be b8 [2] b2 b2 [2] a5 b9 [2] be f7 [2] 83 }

  condition:
    any of them
}