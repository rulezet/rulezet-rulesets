rule TTP_XOR_MULT_DOSStub_86df {
  strings:
    $key_86df = { d2 b7 [2] a6 af [2] e1 ad [2] a6 bc [2] e8 b0 [2] e4 ba [2] f3 b1 [2] e8 ff [2] d5 }

  condition:
    any of them
}