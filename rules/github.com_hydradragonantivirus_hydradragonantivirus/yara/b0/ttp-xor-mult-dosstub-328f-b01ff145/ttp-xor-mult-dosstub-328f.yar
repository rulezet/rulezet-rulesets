rule TTP_XOR_MULT_DOSStub_328f {
  strings:
    $key_328f = { 66 e7 [2] 12 ff [2] 55 fd [2] 12 ec [2] 5c e0 [2] 50 ea [2] 47 e1 [2] 5c af [2] 61 }

  condition:
    any of them
}