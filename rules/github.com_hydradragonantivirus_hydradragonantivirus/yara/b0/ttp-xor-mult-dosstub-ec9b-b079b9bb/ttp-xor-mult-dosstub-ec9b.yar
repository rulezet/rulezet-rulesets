rule TTP_XOR_MULT_DOSStub_ec9b {
  strings:
    $key_ec9b = { b8 f3 [2] cc eb [2] 8b e9 [2] cc f8 [2] 82 f4 [2] 8e fe [2] 99 f5 [2] 82 bb [2] bf }

  condition:
    any of them
}