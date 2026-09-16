rule TTP_XOR_MULT_DOSStub_508f {
  strings:
    $key_508f = { 04 e7 [2] 70 ff [2] 37 fd [2] 70 ec [2] 3e e0 [2] 32 ea [2] 25 e1 [2] 3e af [2] 03 }

  condition:
    any of them
}