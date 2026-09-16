rule TTP_XOR_MULT_DOSStub_83c0 {
  strings:
    $key_83c0 = { d7 a8 [2] a3 b0 [2] e4 b2 [2] a3 a3 [2] ed af [2] e1 a5 [2] f6 ae [2] ed e0 [2] d0 }

  condition:
    any of them
}