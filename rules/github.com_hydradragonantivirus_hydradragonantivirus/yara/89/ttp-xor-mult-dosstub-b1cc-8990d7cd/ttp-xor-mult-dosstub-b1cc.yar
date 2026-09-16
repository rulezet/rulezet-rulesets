rule TTP_XOR_MULT_DOSStub_b1cc {
  strings:
    $key_b1cc = { e5 a4 [2] 91 bc [2] d6 be [2] 91 af [2] df a3 [2] d3 a9 [2] c4 a2 [2] df ec [2] e2 }

  condition:
    any of them
}