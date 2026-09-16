rule TTP_XOR_MULT_DOSStub_048f {
  strings:
    $key_048f = { 50 e7 [2] 24 ff [2] 63 fd [2] 24 ec [2] 6a e0 [2] 66 ea [2] 71 e1 [2] 6a af [2] 57 }

  condition:
    any of them
}