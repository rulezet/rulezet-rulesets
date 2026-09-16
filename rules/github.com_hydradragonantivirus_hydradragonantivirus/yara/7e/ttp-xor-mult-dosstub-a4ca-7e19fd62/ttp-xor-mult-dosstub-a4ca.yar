rule TTP_XOR_MULT_DOSStub_a4ca {
  strings:
    $key_a4ca = { f0 a2 [2] 84 ba [2] c3 b8 [2] 84 a9 [2] ca a5 [2] c6 af [2] d1 a4 [2] ca ea [2] f7 }

  condition:
    any of them
}