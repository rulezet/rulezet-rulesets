rule TTP_XOR_MULT_DOSStub_2d8f {
  strings:
    $key_2d8f = { 79 e7 [2] 0d ff [2] 4a fd [2] 0d ec [2] 43 e0 [2] 4f ea [2] 58 e1 [2] 43 af [2] 7e }

  condition:
    any of them
}