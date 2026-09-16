rule TTP_XOR_MULT_DOSStub_d0c3 {
  strings:
    $key_d0c3 = { 84 ab [2] f0 b3 [2] b7 b1 [2] f0 a0 [2] be ac [2] b2 a6 [2] a5 ad [2] be e3 [2] 83 }

  condition:
    any of them
}