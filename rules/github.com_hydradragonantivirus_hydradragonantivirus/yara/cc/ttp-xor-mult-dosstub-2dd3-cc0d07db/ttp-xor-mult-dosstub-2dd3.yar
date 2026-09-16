rule TTP_XOR_MULT_DOSStub_2dd3 {
  strings:
    $key_2dd3 = { 79 bb [2] 0d a3 [2] 4a a1 [2] 0d b0 [2] 43 bc [2] 4f b6 [2] 58 bd [2] 43 f3 [2] 7e }

  condition:
    any of them
}