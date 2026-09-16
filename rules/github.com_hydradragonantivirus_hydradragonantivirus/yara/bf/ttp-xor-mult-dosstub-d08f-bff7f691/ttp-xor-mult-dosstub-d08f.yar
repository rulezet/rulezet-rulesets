rule TTP_XOR_MULT_DOSStub_d08f {
  strings:
    $key_d08f = { 84 e7 [2] f0 ff [2] b7 fd [2] f0 ec [2] be e0 [2] b2 ea [2] a5 e1 [2] be af [2] 83 }

  condition:
    any of them
}