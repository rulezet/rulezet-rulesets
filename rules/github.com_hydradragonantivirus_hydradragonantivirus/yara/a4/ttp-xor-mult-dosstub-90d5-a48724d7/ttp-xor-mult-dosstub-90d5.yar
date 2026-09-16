rule TTP_XOR_MULT_DOSStub_90d5 {
  strings:
    $key_90d5 = { c4 bd [2] b0 a5 [2] f7 a7 [2] b0 b6 [2] fe ba [2] f2 b0 [2] e5 bb [2] fe f5 [2] c3 }

  condition:
    any of them
}