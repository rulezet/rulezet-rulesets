rule TTP_XOR_MULT_DOSStub_b7ca {
  strings:
    $key_b7ca = { e3 a2 [2] 97 ba [2] d0 b8 [2] 97 a9 [2] d9 a5 [2] d5 af [2] c2 a4 [2] d9 ea [2] e4 }

  condition:
    any of them
}