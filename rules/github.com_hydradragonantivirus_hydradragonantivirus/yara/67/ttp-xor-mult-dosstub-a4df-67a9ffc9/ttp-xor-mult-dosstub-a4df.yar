rule TTP_XOR_MULT_DOSStub_a4df {
  strings:
    $key_a4df = { f0 b7 [2] 84 af [2] c3 ad [2] 84 bc [2] ca b0 [2] c6 ba [2] d1 b1 [2] ca ff [2] f7 }

  condition:
    any of them
}