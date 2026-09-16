rule TTP_XOR_MULT_DOSStub_458f {
  strings:
    $key_458f = { 11 e7 [2] 65 ff [2] 22 fd [2] 65 ec [2] 2b e0 [2] 27 ea [2] 30 e1 [2] 2b af [2] 16 }

  condition:
    any of them
}