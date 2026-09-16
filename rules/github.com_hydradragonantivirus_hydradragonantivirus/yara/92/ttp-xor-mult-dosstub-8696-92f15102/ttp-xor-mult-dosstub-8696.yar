rule TTP_XOR_MULT_DOSStub_8696 {
  strings:
    $key_8696 = { d2 fe [2] a6 e6 [2] e1 e4 [2] a6 f5 [2] e8 f9 [2] e4 f3 [2] f3 f8 [2] e8 b6 [2] d5 }

  condition:
    any of them
}