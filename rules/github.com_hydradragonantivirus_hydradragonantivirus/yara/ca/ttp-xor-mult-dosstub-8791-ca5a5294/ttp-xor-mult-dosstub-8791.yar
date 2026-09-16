rule TTP_XOR_MULT_DOSStub_8791 {
  strings:
    $key_8791 = { d3 f9 [2] a7 e1 [2] e0 e3 [2] a7 f2 [2] e9 fe [2] e5 f4 [2] f2 ff [2] e9 b1 [2] d4 }

  condition:
    any of them
}