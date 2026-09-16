rule TTP_XOR_MULT_DOSStub_708f {
  strings:
    $key_708f = { 24 e7 [2] 50 ff [2] 17 fd [2] 50 ec [2] 1e e0 [2] 12 ea [2] 05 e1 [2] 1e af [2] 23 }

  condition:
    any of them
}