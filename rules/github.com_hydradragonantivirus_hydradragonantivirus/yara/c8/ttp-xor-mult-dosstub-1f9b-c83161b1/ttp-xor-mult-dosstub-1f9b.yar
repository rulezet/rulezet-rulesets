rule TTP_XOR_MULT_DOSStub_1f9b {
  strings:
    $key_1f9b = { 4b f3 [2] 3f eb [2] 78 e9 [2] 3f f8 [2] 71 f4 [2] 7d fe [2] 6a f5 [2] 71 bb [2] 4c }

  condition:
    any of them
}