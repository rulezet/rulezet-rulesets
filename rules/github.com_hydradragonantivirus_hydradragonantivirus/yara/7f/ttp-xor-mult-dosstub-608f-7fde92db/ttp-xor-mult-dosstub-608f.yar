rule TTP_XOR_MULT_DOSStub_608f {
  strings:
    $key_608f = { 34 e7 [2] 40 ff [2] 07 fd [2] 40 ec [2] 0e e0 [2] 02 ea [2] 15 e1 [2] 0e af [2] 33 }

  condition:
    any of them
}