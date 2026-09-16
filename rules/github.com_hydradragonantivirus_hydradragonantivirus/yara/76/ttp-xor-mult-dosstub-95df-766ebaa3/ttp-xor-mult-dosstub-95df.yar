rule TTP_XOR_MULT_DOSStub_95df {
  strings:
    $key_95df = { c1 b7 [2] b5 af [2] f2 ad [2] b5 bc [2] fb b0 [2] f7 ba [2] e0 b1 [2] fb ff [2] c6 }

  condition:
    any of them
}