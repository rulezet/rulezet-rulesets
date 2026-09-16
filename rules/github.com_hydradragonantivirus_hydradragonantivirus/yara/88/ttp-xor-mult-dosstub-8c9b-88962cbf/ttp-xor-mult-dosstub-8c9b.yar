rule TTP_XOR_MULT_DOSStub_8c9b {
  strings:
    $key_8c9b = { d8 f3 [2] ac eb [2] eb e9 [2] ac f8 [2] e2 f4 [2] ee fe [2] f9 f5 [2] e2 bb [2] df }

  condition:
    any of them
}