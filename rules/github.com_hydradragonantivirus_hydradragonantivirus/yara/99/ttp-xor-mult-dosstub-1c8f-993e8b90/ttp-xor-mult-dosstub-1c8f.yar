rule TTP_XOR_MULT_DOSStub_1c8f {
  strings:
    $key_1c8f = { 48 e7 [2] 3c ff [2] 7b fd [2] 3c ec [2] 72 e0 [2] 7e ea [2] 69 e1 [2] 72 af [2] 4f }

  condition:
    any of them
}