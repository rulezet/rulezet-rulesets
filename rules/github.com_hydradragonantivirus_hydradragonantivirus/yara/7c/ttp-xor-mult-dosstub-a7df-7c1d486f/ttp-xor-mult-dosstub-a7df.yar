rule TTP_XOR_MULT_DOSStub_a7df {
  strings:
    $key_a7df = { f3 b7 [2] 87 af [2] c0 ad [2] 87 bc [2] c9 b0 [2] c5 ba [2] d2 b1 [2] c9 ff [2] f4 }

  condition:
    any of them
}