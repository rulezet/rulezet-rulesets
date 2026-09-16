rule TTP_XOR_MULT_DOSStub_7d9b {
  strings:
    $key_7d9b = { 29 f3 [2] 5d eb [2] 1a e9 [2] 5d f8 [2] 13 f4 [2] 1f fe [2] 08 f5 [2] 13 bb [2] 2e }

  condition:
    any of them
}