rule TTP_XOR_MULT_DOSStub_599b {
  strings:
    $key_599b = { 0d f3 [2] 79 eb [2] 3e e9 [2] 79 f8 [2] 37 f4 [2] 3b fe [2] 2c f5 [2] 37 bb [2] 0a }

  condition:
    any of them
}