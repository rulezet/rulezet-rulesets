rule TTP_XOR_MULT_DOSStub_8c97 {
  strings:
    $key_8c97 = { d8 ff [2] ac e7 [2] eb e5 [2] ac f4 [2] e2 f8 [2] ee f2 [2] f9 f9 [2] e2 b7 [2] df }

  condition:
    any of them
}