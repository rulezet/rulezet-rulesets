rule TTP_XOR_MULT_DOSStub_258f {
  strings:
    $key_258f = { 71 e7 [2] 05 ff [2] 42 fd [2] 05 ec [2] 4b e0 [2] 47 ea [2] 50 e1 [2] 4b af [2] 76 }

  condition:
    any of them
}