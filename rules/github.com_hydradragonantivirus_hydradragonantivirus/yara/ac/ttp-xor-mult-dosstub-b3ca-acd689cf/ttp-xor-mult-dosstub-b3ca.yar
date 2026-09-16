rule TTP_XOR_MULT_DOSStub_b3ca {
  strings:
    $key_b3ca = { e7 a2 [2] 93 ba [2] d4 b8 [2] 93 a9 [2] dd a5 [2] d1 af [2] c6 a4 [2] dd ea [2] e0 }

  condition:
    any of them
}