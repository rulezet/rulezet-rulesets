rule TTP_XOR_MULT_DOSStub_8682 {
  strings:
    $key_8682 = { d2 ea [2] a6 f2 [2] e1 f0 [2] a6 e1 [2] e8 ed [2] e4 e7 [2] f3 ec [2] e8 a2 [2] d5 }

  condition:
    any of them
}