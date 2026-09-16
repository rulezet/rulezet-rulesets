rule TTP_XOR_MULT_DOSStub_199b {
  strings:
    $key_199b = { 4d f3 [2] 39 eb [2] 7e e9 [2] 39 f8 [2] 77 f4 [2] 7b fe [2] 6c f5 [2] 77 bb [2] 4a }

  condition:
    any of them
}