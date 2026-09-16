rule TTP_XOR_MULT_DOSStub_478f {
  strings:
    $key_478f = { 13 e7 [2] 67 ff [2] 20 fd [2] 67 ec [2] 29 e0 [2] 25 ea [2] 32 e1 [2] 29 af [2] 14 }

  condition:
    any of them
}