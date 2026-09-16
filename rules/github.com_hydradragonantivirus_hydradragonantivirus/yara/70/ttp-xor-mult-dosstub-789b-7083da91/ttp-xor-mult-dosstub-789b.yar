rule TTP_XOR_MULT_DOSStub_789b {
  strings:
    $key_789b = { 2c f3 [2] 58 eb [2] 1f e9 [2] 58 f8 [2] 16 f4 [2] 1a fe [2] 0d f5 [2] 16 bb [2] 2b }

  condition:
    any of them
}