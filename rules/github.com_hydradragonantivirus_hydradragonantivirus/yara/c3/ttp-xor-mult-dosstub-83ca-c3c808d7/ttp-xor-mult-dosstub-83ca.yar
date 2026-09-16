rule TTP_XOR_MULT_DOSStub_83ca {
  strings:
    $key_83ca = { d7 a2 [2] a3 ba [2] e4 b8 [2] a3 a9 [2] ed a5 [2] e1 af [2] f6 a4 [2] ed ea [2] d0 }

  condition:
    any of them
}