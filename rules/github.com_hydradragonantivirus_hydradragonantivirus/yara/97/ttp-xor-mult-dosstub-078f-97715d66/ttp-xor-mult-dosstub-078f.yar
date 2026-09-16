rule TTP_XOR_MULT_DOSStub_078f {
  strings:
    $key_078f = { 53 e7 [2] 27 ff [2] 60 fd [2] 27 ec [2] 69 e0 [2] 65 ea [2] 72 e1 [2] 69 af [2] 54 }

  condition:
    any of them
}