rule TTP_XOR_MULT_DOSStub_809b {
  strings:
    $key_809b = { d4 f3 [2] a0 eb [2] e7 e9 [2] a0 f8 [2] ee f4 [2] e2 fe [2] f5 f5 [2] ee bb [2] d3 }

  condition:
    any of them
}