rule TTP_XOR_MULT_DOSStub_7dd5 {
  strings:
    $key_7dd5 = { 29 bd [2] 5d a5 [2] 1a a7 [2] 5d b6 [2] 13 ba [2] 1f b0 [2] 08 bb [2] 13 f5 [2] 2e }

  condition:
    any of them
}