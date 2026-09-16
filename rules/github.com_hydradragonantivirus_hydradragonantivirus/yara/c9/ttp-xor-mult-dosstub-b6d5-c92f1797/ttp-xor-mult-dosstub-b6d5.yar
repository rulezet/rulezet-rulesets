rule TTP_XOR_MULT_DOSStub_b6d5 {
  strings:
    $key_b6d5 = { e2 bd [2] 96 a5 [2] d1 a7 [2] 96 b6 [2] d8 ba [2] d4 b0 [2] c3 bb [2] d8 f5 [2] e5 }

  condition:
    any of them
}