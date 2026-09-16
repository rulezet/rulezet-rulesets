rule TTP_XOR_MULT_DOSStub_7dd3 {
  strings:
    $key_7dd3 = { 29 bb [2] 5d a3 [2] 1a a1 [2] 5d b0 [2] 13 bc [2] 1f b6 [2] 08 bd [2] 13 f3 [2] 2e }

  condition:
    any of them
}