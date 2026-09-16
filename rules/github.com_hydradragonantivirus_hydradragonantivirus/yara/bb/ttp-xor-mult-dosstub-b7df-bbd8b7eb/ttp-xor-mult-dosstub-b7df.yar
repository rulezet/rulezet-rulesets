rule TTP_XOR_MULT_DOSStub_b7df {
  strings:
    $key_b7df = { e3 b7 [2] 97 af [2] d0 ad [2] 97 bc [2] d9 b0 [2] d5 ba [2] c2 b1 [2] d9 ff [2] e4 }

  condition:
    any of them
}