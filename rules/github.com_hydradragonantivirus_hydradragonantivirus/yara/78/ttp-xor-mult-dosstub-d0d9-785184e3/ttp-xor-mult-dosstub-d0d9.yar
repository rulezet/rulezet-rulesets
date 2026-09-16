rule TTP_XOR_MULT_DOSStub_d0d9 {
  strings:
    $key_d0d9 = { 84 b1 [2] f0 a9 [2] b7 ab [2] f0 ba [2] be b6 [2] b2 bc [2] a5 b7 [2] be f9 [2] 83 }

  condition:
    any of them
}