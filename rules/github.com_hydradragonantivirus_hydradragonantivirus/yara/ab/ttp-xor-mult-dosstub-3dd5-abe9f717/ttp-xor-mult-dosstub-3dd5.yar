rule TTP_XOR_MULT_DOSStub_3dd5 {
  strings:
    $key_3dd5 = { 69 bd [2] 1d a5 [2] 5a a7 [2] 1d b6 [2] 53 ba [2] 5f b0 [2] 48 bb [2] 53 f5 [2] 6e }

  condition:
    any of them
}