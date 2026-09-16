rule TTP_XOR_MULT_DOSStub_d5d4 {
  strings:
    $key_d5d4 = { 81 bc [2] f5 a4 [2] b2 a6 [2] f5 b7 [2] bb bb [2] b7 b1 [2] a0 ba [2] bb f4 [2] 86 }

  condition:
    any of them
}