rule TTP_XOR_MULT_DOSStub_038f {
  strings:
    $key_038f = { 57 e7 [2] 23 ff [2] 64 fd [2] 23 ec [2] 6d e0 [2] 61 ea [2] 76 e1 [2] 6d af [2] 50 }

  condition:
    any of them
}