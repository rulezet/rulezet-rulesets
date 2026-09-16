rule TTP_XOR_MULT_DOSStub_928f {
  strings:
    $key_928f = { c6 e7 [2] b2 ff [2] f5 fd [2] b2 ec [2] fc e0 [2] f0 ea [2] e7 e1 [2] fc af [2] c1 }

  condition:
    any of them
}