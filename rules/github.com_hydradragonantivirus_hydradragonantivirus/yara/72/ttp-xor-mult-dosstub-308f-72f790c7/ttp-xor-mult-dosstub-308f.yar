rule TTP_XOR_MULT_DOSStub_308f {
  strings:
    $key_308f = { 64 e7 [2] 10 ff [2] 57 fd [2] 10 ec [2] 5e e0 [2] 52 ea [2] 45 e1 [2] 5e af [2] 63 }

  condition:
    any of them
}