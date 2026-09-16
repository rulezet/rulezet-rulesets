rule TTP_XOR_MULT_DOSStub_80df {
  strings:
    $key_80df = { d4 b7 [2] a0 af [2] e7 ad [2] a0 bc [2] ee b0 [2] e2 ba [2] f5 b1 [2] ee ff [2] d3 }

  condition:
    any of them
}