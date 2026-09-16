rule TTP_XOR_MULT_DOSStub_7f9b {
  strings:
    $key_7f9b = { 2b f3 [2] 5f eb [2] 18 e9 [2] 5f f8 [2] 11 f4 [2] 1d fe [2] 0a f5 [2] 11 bb [2] 2c }

  condition:
    any of them
}