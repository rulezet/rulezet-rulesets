rule TTP_XOR_MULT_DOSStub_bd9b {
  strings:
    $key_bd9b = { e9 f3 [2] 9d eb [2] da e9 [2] 9d f8 [2] d3 f4 [2] df fe [2] c8 f5 [2] d3 bb [2] ee }

  condition:
    any of them
}