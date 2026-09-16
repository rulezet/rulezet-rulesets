rule TTP_XOR_MULT_DOSStub_97df {
  strings:
    $key_97df = { c3 b7 [2] b7 af [2] f0 ad [2] b7 bc [2] f9 b0 [2] f5 ba [2] e2 b1 [2] f9 ff [2] c4 }

  condition:
    any of them
}