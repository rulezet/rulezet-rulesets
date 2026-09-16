rule TTP_XOR_MULT_DOSStub_389b {
  strings:
    $key_389b = { 6c f3 [2] 18 eb [2] 5f e9 [2] 18 f8 [2] 56 f4 [2] 5a fe [2] 4d f5 [2] 56 bb [2] 6b }

  condition:
    any of them
}