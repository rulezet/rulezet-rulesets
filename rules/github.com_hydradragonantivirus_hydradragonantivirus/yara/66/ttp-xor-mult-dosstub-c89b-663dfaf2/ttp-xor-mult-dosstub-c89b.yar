rule TTP_XOR_MULT_DOSStub_c89b {
  strings:
    $key_c89b = { 9c f3 [2] e8 eb [2] af e9 [2] e8 f8 [2] a6 f4 [2] aa fe [2] bd f5 [2] a6 bb [2] 9b }

  condition:
    any of them
}