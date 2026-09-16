rule TTP_XOR_MULT_DOSStub_b4df {
  strings:
    $key_b4df = { e0 b7 [2] 94 af [2] d3 ad [2] 94 bc [2] da b0 [2] d6 ba [2] c1 b1 [2] da ff [2] e7 }

  condition:
    any of them
}