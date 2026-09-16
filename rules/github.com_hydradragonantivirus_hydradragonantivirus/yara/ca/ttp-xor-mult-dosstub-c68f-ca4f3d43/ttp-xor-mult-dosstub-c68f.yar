rule TTP_XOR_MULT_DOSStub_c68f {
  strings:
    $key_c68f = { 92 e7 [2] e6 ff [2] a1 fd [2] e6 ec [2] a8 e0 [2] a4 ea [2] b3 e1 [2] a8 af [2] 95 }

  condition:
    any of them
}