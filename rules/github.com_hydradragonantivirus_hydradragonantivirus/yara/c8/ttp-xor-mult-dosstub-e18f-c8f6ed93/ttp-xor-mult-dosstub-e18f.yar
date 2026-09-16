rule TTP_XOR_MULT_DOSStub_e18f {
  strings:
    $key_e18f = { b5 e7 [2] c1 ff [2] 86 fd [2] c1 ec [2] 8f e0 [2] 83 ea [2] 94 e1 [2] 8f af [2] b2 }

  condition:
    any of them
}