rule TTP_XOR_MULT_DOSStub_889b {
  strings:
    $key_889b = { dc f3 [2] a8 eb [2] ef e9 [2] a8 f8 [2] e6 f4 [2] ea fe [2] fd f5 [2] e6 bb [2] db }

  condition:
    any of them
}