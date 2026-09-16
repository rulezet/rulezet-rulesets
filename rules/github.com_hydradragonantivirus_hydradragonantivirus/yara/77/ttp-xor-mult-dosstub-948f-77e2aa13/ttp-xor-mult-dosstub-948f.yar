rule TTP_XOR_MULT_DOSStub_948f {
  strings:
    $key_948f = { c0 e7 [2] b4 ff [2] f3 fd [2] b4 ec [2] fa e0 [2] f6 ea [2] e1 e1 [2] fa af [2] c7 }

  condition:
    any of them
}