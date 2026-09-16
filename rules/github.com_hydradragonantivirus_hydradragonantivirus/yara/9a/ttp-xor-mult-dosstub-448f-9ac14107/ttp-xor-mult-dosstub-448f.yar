rule TTP_XOR_MULT_DOSStub_448f {
  strings:
    $key_448f = { 10 e7 [2] 64 ff [2] 23 fd [2] 64 ec [2] 2a e0 [2] 26 ea [2] 31 e1 [2] 2a af [2] 17 }

  condition:
    any of them
}