rule TTP_XOR_MULT_DOSStub_d691 {
  strings:
    $key_d691 = { 82 f9 [2] f6 e1 [2] b1 e3 [2] f6 f2 [2] b8 fe [2] b4 f4 [2] a3 ff [2] b8 b1 [2] 85 }

  condition:
    any of them
}