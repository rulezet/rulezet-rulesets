rule TTP_XOR_MULT_DOSStub_3a8f {
  strings:
    $key_3a8f = { 6e e7 [2] 1a ff [2] 5d fd [2] 1a ec [2] 54 e0 [2] 58 ea [2] 4f e1 [2] 54 af [2] 69 }

  condition:
    any of them
}