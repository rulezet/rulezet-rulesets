rule TTP_XOR_MULT_DOSStub_589b {
  strings:
    $key_589b = { 0c f3 [2] 78 eb [2] 3f e9 [2] 78 f8 [2] 36 f4 [2] 3a fe [2] 2d f5 [2] 36 bb [2] 0b }

  condition:
    any of them
}