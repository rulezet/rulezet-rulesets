rule TTP_XOR_MULT_DOSStub_4d9b {
  strings:
    $key_4d9b = { 19 f3 [2] 6d eb [2] 2a e9 [2] 6d f8 [2] 23 f4 [2] 2f fe [2] 38 f5 [2] 23 bb [2] 1e }

  condition:
    any of them
}