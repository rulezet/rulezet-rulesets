rule TTP_XOR_MULT_DOSStub_b6df {
  strings:
    $key_b6df = { e2 b7 [2] 96 af [2] d1 ad [2] 96 bc [2] d8 b0 [2] d4 ba [2] c3 b1 [2] d8 ff [2] e5 }

  condition:
    any of them
}