rule TTP_XOR_MULT_DOSStub_8790 {
  strings:
    $key_8790 = { d3 f8 [2] a7 e0 [2] e0 e2 [2] a7 f3 [2] e9 ff [2] e5 f5 [2] f2 fe [2] e9 b0 [2] d4 }

  condition:
    any of them
}