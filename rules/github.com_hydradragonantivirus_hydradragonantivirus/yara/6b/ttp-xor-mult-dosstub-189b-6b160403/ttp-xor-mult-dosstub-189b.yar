rule TTP_XOR_MULT_DOSStub_189b {
  strings:
    $key_189b = { 4c f3 [2] 38 eb [2] 7f e9 [2] 38 f8 [2] 76 f4 [2] 7a fe [2] 6d f5 [2] 76 bb [2] 4b }

  condition:
    any of them
}