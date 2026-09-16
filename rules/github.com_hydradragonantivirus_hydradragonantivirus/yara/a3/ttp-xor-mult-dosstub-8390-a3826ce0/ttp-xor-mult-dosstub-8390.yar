rule TTP_XOR_MULT_DOSStub_8390 {
  strings:
    $key_8390 = { d7 f8 [2] a3 e0 [2] e4 e2 [2] a3 f3 [2] ed ff [2] e1 f5 [2] f6 fe [2] ed b0 [2] d0 }

  condition:
    any of them
}