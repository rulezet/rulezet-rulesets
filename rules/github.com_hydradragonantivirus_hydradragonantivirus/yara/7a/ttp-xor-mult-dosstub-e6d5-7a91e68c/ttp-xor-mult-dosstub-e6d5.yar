rule TTP_XOR_MULT_DOSStub_e6d5 {
  strings:
    $key_e6d5 = { b2 bd [2] c6 a5 [2] 81 a7 [2] c6 b6 [2] 88 ba [2] 84 b0 [2] 93 bb [2] 88 f5 [2] b5 }

  condition:
    any of them
}