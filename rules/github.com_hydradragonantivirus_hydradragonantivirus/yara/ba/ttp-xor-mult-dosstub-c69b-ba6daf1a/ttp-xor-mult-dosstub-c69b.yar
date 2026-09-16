rule TTP_XOR_MULT_DOSStub_c69b {
  strings:
    $key_c69b = { 92 f3 [2] e6 eb [2] a1 e9 [2] e6 f8 [2] a8 f4 [2] a4 fe [2] b3 f5 [2] a8 bb [2] 95 }

  condition:
    any of them
}