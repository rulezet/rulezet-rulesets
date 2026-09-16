rule TTP_XOR_MULT_DOSStub_758f {
  strings:
    $key_758f = { 21 e7 [2] 55 ff [2] 12 fd [2] 55 ec [2] 1b e0 [2] 17 ea [2] 00 e1 [2] 1b af [2] 26 }

  condition:
    any of them
}