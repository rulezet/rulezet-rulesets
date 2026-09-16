rule TTP_XOR_MULT_DOSStub_3e9b {
  strings:
    $key_3e9b = { 6a f3 [2] 1e eb [2] 59 e9 [2] 1e f8 [2] 50 f4 [2] 5c fe [2] 4b f5 [2] 50 bb [2] 6d }

  condition:
    any of them
}