rule TTP_XOR_MULT_DOSStub_108f {
  strings:
    $key_108f = { 44 e7 [2] 30 ff [2] 77 fd [2] 30 ec [2] 7e e0 [2] 72 ea [2] 65 e1 [2] 7e af [2] 43 }

  condition:
    any of them
}