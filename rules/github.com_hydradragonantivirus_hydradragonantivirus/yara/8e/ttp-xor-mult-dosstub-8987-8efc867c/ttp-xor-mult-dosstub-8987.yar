rule TTP_XOR_MULT_DOSStub_8987 {
  strings:
    $key_8987 = { dd ef [2] a9 f7 [2] ee f5 [2] a9 e4 [2] e7 e8 [2] eb e2 [2] fc e9 [2] e7 a7 [2] da }

  condition:
    any of them
}