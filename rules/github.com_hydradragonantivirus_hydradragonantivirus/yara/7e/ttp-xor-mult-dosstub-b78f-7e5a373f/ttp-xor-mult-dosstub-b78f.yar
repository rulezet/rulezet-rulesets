rule TTP_XOR_MULT_DOSStub_b78f {
  strings:
    $key_b78f = { e3 e7 [2] 97 ff [2] d0 fd [2] 97 ec [2] d9 e0 [2] d5 ea [2] c2 e1 [2] d9 af [2] e4 }

  condition:
    any of them
}