rule TTP_XOR_MULT_DOSStub_148f {
  strings:
    $key_148f = { 40 e7 [2] 34 ff [2] 73 fd [2] 34 ec [2] 7a e0 [2] 76 ea [2] 61 e1 [2] 7a af [2] 47 }

  condition:
    any of them
}