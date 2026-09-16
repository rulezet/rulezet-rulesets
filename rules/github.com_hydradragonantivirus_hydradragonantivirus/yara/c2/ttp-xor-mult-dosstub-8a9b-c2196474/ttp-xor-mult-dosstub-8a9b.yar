rule TTP_XOR_MULT_DOSStub_8a9b {
  strings:
    $key_8a9b = { de f3 [2] aa eb [2] ed e9 [2] aa f8 [2] e4 f4 [2] e8 fe [2] ff f5 [2] e4 bb [2] d9 }

  condition:
    any of them
}