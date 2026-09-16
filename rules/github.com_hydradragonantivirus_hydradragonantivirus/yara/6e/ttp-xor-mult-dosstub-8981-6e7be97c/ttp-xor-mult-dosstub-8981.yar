rule TTP_XOR_MULT_DOSStub_8981 {
  strings:
    $key_8981 = { dd e9 [2] a9 f1 [2] ee f3 [2] a9 e2 [2] e7 ee [2] eb e4 [2] fc ef [2] e7 a1 [2] da }

  condition:
    any of them
}