rule TTP_XOR_MULT_DOSStub_e68f {
  strings:
    $key_e68f = { b2 e7 [2] c6 ff [2] 81 fd [2] c6 ec [2] 88 e0 [2] 84 ea [2] 93 e1 [2] 88 af [2] b5 }

  condition:
    any of them
}