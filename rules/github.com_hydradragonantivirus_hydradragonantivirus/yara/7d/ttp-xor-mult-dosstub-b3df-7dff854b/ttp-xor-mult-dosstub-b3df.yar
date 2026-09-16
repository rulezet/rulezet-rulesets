rule TTP_XOR_MULT_DOSStub_b3df {
  strings:
    $key_b3df = { e7 b7 [2] 93 af [2] d4 ad [2] 93 bc [2] dd b0 [2] d1 ba [2] c6 b1 [2] dd ff [2] e0 }

  condition:
    any of them
}