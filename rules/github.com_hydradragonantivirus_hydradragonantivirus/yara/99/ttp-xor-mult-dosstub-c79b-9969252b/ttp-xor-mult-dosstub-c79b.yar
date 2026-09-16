rule TTP_XOR_MULT_DOSStub_c79b {
  strings:
    $key_c79b = { 93 f3 [2] e7 eb [2] a0 e9 [2] e7 f8 [2] a9 f4 [2] a5 fe [2] b2 f5 [2] a9 bb [2] 94 }

  condition:
    any of them
}