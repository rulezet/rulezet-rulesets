rule TTP_XOR_MULT_DOSStub_df9b {
  strings:
    $key_df9b = { 8b f3 [2] ff eb [2] b8 e9 [2] ff f8 [2] b1 f4 [2] bd fe [2] aa f5 [2] b1 bb [2] 8c }

  condition:
    any of them
}