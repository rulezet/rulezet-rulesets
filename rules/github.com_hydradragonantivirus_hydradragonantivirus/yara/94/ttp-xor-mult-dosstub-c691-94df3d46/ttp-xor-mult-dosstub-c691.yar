rule TTP_XOR_MULT_DOSStub_c691 {
  strings:
    $key_c691 = { 92 f9 [2] e6 e1 [2] a1 e3 [2] e6 f2 [2] a8 fe [2] a4 f4 [2] b3 ff [2] a8 b1 [2] 95 }

  condition:
    any of them
}