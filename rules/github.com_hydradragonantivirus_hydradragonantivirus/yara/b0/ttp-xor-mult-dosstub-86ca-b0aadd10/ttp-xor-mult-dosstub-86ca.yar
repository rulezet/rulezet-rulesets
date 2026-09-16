rule TTP_XOR_MULT_DOSStub_86ca {
  strings:
    $key_86ca = { d2 a2 [2] a6 ba [2] e1 b8 [2] a6 a9 [2] e8 a5 [2] e4 af [2] f3 a4 [2] e8 ea [2] d5 }

  condition:
    any of them
}