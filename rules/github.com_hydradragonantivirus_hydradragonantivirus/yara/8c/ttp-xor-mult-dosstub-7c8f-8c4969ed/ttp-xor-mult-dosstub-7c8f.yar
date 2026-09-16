rule TTP_XOR_MULT_DOSStub_7c8f {
  strings:
    $key_7c8f = { 28 e7 [2] 5c ff [2] 1b fd [2] 5c ec [2] 12 e0 [2] 1e ea [2] 09 e1 [2] 12 af [2] 2f }

  condition:
    any of them
}