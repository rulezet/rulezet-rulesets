rule TTP_XOR_MULT_DOSStub_b4cc {
  strings:
    $key_b4cc = { e0 a4 [2] 94 bc [2] d3 be [2] 94 af [2] da a3 [2] d6 a9 [2] c1 a2 [2] da ec [2] e7 }

  condition:
    any of them
}