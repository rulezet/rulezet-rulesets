rule TTP_XOR_MULT_DOSStub_0e9b {
  strings:
    $key_0e9b = { 5a f3 [2] 2e eb [2] 69 e9 [2] 2e f8 [2] 60 f4 [2] 6c fe [2] 7b f5 [2] 60 bb [2] 5d }

  condition:
    any of them
}