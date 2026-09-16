rule TTP_XOR_MULT_DOSStub_83df {
  strings:
    $key_83df = { d7 b7 [2] a3 af [2] e4 ad [2] a3 bc [2] ed b0 [2] e1 ba [2] f6 b1 [2] ed ff [2] d0 }

  condition:
    any of them
}