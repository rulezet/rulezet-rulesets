rule TTP_XOR_MULT_DOSStub_fc9b {
  strings:
    $key_fc9b = { a8 f3 [2] dc eb [2] 9b e9 [2] dc f8 [2] 92 f4 [2] 9e fe [2] 89 f5 [2] 92 bb [2] af }

  condition:
    any of them
}