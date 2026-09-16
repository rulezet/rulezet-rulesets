rule TTP_XOR_MULT_DOSStub_d0d2 {
  strings:
    $key_d0d2 = { 84 ba [2] f0 a2 [2] b7 a0 [2] f0 b1 [2] be bd [2] b2 b7 [2] a5 bc [2] be f2 [2] 83 }

  condition:
    any of them
}