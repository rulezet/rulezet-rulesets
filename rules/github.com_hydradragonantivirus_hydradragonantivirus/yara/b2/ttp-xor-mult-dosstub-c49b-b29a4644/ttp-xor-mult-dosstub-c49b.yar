rule TTP_XOR_MULT_DOSStub_c49b {
  strings:
    $key_c49b = { 90 f3 [2] e4 eb [2] a3 e9 [2] e4 f8 [2] aa f4 [2] a6 fe [2] b1 f5 [2] aa bb [2] 97 }

  condition:
    any of them
}