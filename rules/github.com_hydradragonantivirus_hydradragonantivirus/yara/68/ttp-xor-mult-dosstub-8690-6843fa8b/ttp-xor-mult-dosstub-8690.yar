rule TTP_XOR_MULT_DOSStub_8690 {
  strings:
    $key_8690 = { d2 f8 [2] a6 e0 [2] e1 e2 [2] a6 f3 [2] e8 ff [2] e4 f5 [2] f3 fe [2] e8 b0 [2] d5 }

  condition:
    any of them
}