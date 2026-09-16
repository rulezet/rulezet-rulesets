rule TTP_XOR_MULT_DOSStub_b5cc {
  strings:
    $key_b5cc = { e1 a4 [2] 95 bc [2] d2 be [2] 95 af [2] db a3 [2] d7 a9 [2] c0 a2 [2] db ec [2] e6 }

  condition:
    any of them
}