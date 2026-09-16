rule TTP_XOR_MULT_DOSStub_d0d6 {
  strings:
    $key_d0d6 = { 84 be [2] f0 a6 [2] b7 a4 [2] f0 b5 [2] be b9 [2] b2 b3 [2] a5 b8 [2] be f6 [2] 83 }

  condition:
    any of them
}