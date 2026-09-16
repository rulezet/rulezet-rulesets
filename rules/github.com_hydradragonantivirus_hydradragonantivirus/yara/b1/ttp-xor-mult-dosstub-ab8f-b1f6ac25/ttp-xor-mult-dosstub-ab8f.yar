rule TTP_XOR_MULT_DOSStub_ab8f {
  strings:
    $key_ab8f = { ff e7 [2] 8b ff [2] cc fd [2] 8b ec [2] c5 e0 [2] c9 ea [2] de e1 [2] c5 af [2] f8 }

  condition:
    any of them
}