rule TTP_XOR_MULT_DOSStub_4c8f {
  strings:
    $key_4c8f = { 18 e7 [2] 6c ff [2] 2b fd [2] 6c ec [2] 22 e0 [2] 2e ea [2] 39 e1 [2] 22 af [2] 1f }

  condition:
    any of them
}