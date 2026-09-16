rule TTP_XOR_MULT_DOSStub_8c90 {
  strings:
    $key_8c90 = { d8 f8 [2] ac e0 [2] eb e2 [2] ac f3 [2] e2 ff [2] ee f5 [2] f9 fe [2] e2 b0 [2] df }

  condition:
    any of them
}