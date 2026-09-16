rule TTP_XOR_MULT_DOSStub_ec96 {
  strings:
    $key_ec96 = { b8 fe [2] cc e6 [2] 8b e4 [2] cc f5 [2] 82 f9 [2] 8e f3 [2] 99 f8 [2] 82 b6 [2] bf }

  condition:
    any of them
}