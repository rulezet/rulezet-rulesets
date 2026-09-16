rule TTP_XOR_MULT_DOSStub_1d9b {
  strings:
    $key_1d9b = { 49 f3 [2] 3d eb [2] 7a e9 [2] 3d f8 [2] 73 f4 [2] 7f fe [2] 68 f5 [2] 73 bb [2] 4e }

  condition:
    any of them
}