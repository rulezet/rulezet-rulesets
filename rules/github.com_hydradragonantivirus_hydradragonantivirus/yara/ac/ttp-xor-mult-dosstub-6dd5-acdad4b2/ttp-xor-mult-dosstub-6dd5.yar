rule TTP_XOR_MULT_DOSStub_6dd5 {
  strings:
    $key_6dd5 = { 39 bd [2] 4d a5 [2] 0a a7 [2] 4d b6 [2] 03 ba [2] 0f b0 [2] 18 bb [2] 03 f5 [2] 3e }

  condition:
    any of them
}