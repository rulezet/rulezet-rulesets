rule TTP_XOR_MULT_DOSStub_e5d5 {
  strings:
    $key_e5d5 = { b1 bd [2] c5 a5 [2] 82 a7 [2] c5 b6 [2] 8b ba [2] 87 b0 [2] 90 bb [2] 8b f5 [2] b6 }

  condition:
    any of them
}