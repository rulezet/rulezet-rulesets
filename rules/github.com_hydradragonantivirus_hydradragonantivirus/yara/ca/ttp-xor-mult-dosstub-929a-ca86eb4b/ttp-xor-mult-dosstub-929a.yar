rule TTP_XOR_MULT_DOSStub_929a {
  strings:
    $key_929a = { c6 f2 [2] b2 ea [2] f5 e8 [2] b2 f9 [2] fc f5 [2] f0 ff [2] e7 f4 [2] fc ba [2] c1 }

  condition:
    any of them
}