rule TTP_XOR_MULT_DOSStub_a2d5 {
  strings:
    $key_a2d5 = { f6 bd [2] 82 a5 [2] c5 a7 [2] 82 b6 [2] cc ba [2] c0 b0 [2] d7 bb [2] cc f5 [2] f1 }

  condition:
    any of them
}