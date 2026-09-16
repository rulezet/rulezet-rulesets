rule TTP_XOR_MULT_DOSStub_5e9b {
  strings:
    $key_5e9b = { 0a f3 [2] 7e eb [2] 39 e9 [2] 7e f8 [2] 30 f4 [2] 3c fe [2] 2b f5 [2] 30 bb [2] 0d }

  condition:
    any of them
}