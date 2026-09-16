rule TTP_XOR_MULT_DOSStub_028f {
  strings:
    $key_028f = { 56 e7 [2] 22 ff [2] 65 fd [2] 22 ec [2] 6c e0 [2] 60 ea [2] 77 e1 [2] 6c af [2] 51 }

  condition:
    any of them
}