rule TTP_XOR_MULT_DOSStub_b28f {
  strings:
    $key_b28f = { e6 e7 [2] 92 ff [2] d5 fd [2] 92 ec [2] dc e0 [2] d0 ea [2] c7 e1 [2] dc af [2] e1 }

  condition:
    any of them
}