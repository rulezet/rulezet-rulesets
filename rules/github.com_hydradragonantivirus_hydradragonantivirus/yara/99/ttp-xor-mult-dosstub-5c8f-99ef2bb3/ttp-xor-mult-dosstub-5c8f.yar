rule TTP_XOR_MULT_DOSStub_5c8f {
  strings:
    $key_5c8f = { 08 e7 [2] 7c ff [2] 3b fd [2] 7c ec [2] 32 e0 [2] 3e ea [2] 29 e1 [2] 32 af [2] 0f }

  condition:
    any of them
}