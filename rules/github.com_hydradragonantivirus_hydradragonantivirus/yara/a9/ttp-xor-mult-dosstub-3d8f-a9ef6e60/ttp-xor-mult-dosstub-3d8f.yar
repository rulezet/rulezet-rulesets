rule TTP_XOR_MULT_DOSStub_3d8f {
  strings:
    $key_3d8f = { 69 e7 [2] 1d ff [2] 5a fd [2] 1d ec [2] 53 e0 [2] 5f ea [2] 48 e1 [2] 53 af [2] 6e }

  condition:
    any of them
}