rule TTP_XOR_MULT_DOSStub_1d8f {
  strings:
    $key_1d8f = { 49 e7 [2] 3d ff [2] 7a fd [2] 3d ec [2] 73 e0 [2] 7f ea [2] 68 e1 [2] 73 af [2] 4e }

  condition:
    any of them
}