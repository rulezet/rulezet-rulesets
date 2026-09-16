rule TTP_XOR_MULT_DOSStub_a1ca {
  strings:
    $key_a1ca = { f5 a2 [2] 81 ba [2] c6 b8 [2] 81 a9 [2] cf a5 [2] c3 af [2] d4 a4 [2] cf ea [2] f2 }

  condition:
    any of them
}