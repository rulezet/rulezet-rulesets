rule TTP_XOR_MULT_DOSStub_85d5 {
  strings:
    $key_85d5 = { d1 bd [2] a5 a5 [2] e2 a7 [2] a5 b6 [2] eb ba [2] e7 b0 [2] f0 bb [2] eb f5 [2] d6 }

  condition:
    any of them
}