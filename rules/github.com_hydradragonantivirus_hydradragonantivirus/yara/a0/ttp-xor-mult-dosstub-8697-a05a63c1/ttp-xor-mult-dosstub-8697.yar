rule TTP_XOR_MULT_DOSStub_8697 {
  strings:
    $key_8697 = { d2 ff [2] a6 e7 [2] e1 e5 [2] a6 f4 [2] e8 f8 [2] e4 f2 [2] f3 f9 [2] e8 b7 [2] d5 }

  condition:
    any of them
}