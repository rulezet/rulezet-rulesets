rule TTP_XOR_MULT_DOSStub_6e9b {
  strings:
    $key_6e9b = { 3a f3 [2] 4e eb [2] 09 e9 [2] 4e f8 [2] 00 f4 [2] 0c fe [2] 1b f5 [2] 00 bb [2] 3d }

  condition:
    any of them
}