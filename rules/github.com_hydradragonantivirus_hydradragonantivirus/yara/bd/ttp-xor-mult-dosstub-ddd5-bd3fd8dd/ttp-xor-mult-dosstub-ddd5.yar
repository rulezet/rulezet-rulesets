rule TTP_XOR_MULT_DOSStub_ddd5 {
  strings:
    $key_ddd5 = { 89 bd [2] fd a5 [2] ba a7 [2] fd b6 [2] b3 ba [2] bf b0 [2] a8 bb [2] b3 f5 [2] 8e }

  condition:
    any of them
}