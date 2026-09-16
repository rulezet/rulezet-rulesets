rule TTP_XOR_MULT_DOSStub_d0c8 {
  strings:
    $key_d0c8 = { 84 a0 [2] f0 b8 [2] b7 ba [2] f0 ab [2] be a7 [2] b2 ad [2] a5 a6 [2] be e8 [2] 83 }

  condition:
    any of them
}