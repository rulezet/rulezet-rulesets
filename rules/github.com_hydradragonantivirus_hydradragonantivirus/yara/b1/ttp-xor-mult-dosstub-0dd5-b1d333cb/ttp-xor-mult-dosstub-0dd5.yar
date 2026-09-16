rule TTP_XOR_MULT_DOSStub_0dd5 {
  strings:
    $key_0dd5 = { 59 bd [2] 2d a5 [2] 6a a7 [2] 2d b6 [2] 63 ba [2] 6f b0 [2] 78 bb [2] 63 f5 [2] 5e }

  condition:
    any of them
}