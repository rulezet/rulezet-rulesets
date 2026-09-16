rule TTP_XOR_MULT_DOSStub_228f {
  strings:
    $key_228f = { 76 e7 [2] 02 ff [2] 45 fd [2] 02 ec [2] 4c e0 [2] 40 ea [2] 57 e1 [2] 4c af [2] 71 }

  condition:
    any of them
}