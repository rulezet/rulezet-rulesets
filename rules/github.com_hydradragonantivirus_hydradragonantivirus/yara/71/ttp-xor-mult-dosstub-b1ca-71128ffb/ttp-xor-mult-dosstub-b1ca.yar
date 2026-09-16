rule TTP_XOR_MULT_DOSStub_b1ca {
  strings:
    $key_b1ca = { e5 a2 [2] 91 ba [2] d6 b8 [2] 91 a9 [2] df a5 [2] d3 af [2] c4 a4 [2] df ea [2] e2 }

  condition:
    any of them
}