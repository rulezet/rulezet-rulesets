rule TTP_XOR_MULT_DOSStub_97d5 {
  strings:
    $key_97d5 = { c3 bd [2] b7 a5 [2] f0 a7 [2] b7 b6 [2] f9 ba [2] f5 b0 [2] e2 bb [2] f9 f5 [2] c4 }

  condition:
    any of them
}