rule TTP_XOR_MULT_DOSStub_d0d0 {
  strings:
    $key_d0d0 = { 84 b8 [2] f0 a0 [2] b7 a2 [2] f0 b3 [2] be bf [2] b2 b5 [2] a5 be [2] be f0 [2] 83 }

  condition:
    any of them
}