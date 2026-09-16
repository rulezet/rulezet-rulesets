rule TTP_XOR_MULT_DOSStub_3dd3 {
  strings:
    $key_3dd3 = { 69 bb [2] 1d a3 [2] 5a a1 [2] 1d b0 [2] 53 bc [2] 5f b6 [2] 48 bd [2] 53 f3 [2] 6e }

  condition:
    any of them
}