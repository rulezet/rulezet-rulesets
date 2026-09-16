rule TTP_XOR_MULT_DOSStub_128f {
  strings:
    $key_128f = { 46 e7 [2] 32 ff [2] 75 fd [2] 32 ec [2] 7c e0 [2] 70 ea [2] 67 e1 [2] 7c af [2] 41 }

  condition:
    any of them
}