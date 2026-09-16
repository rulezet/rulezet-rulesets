rule TTP_XOR_MULT_DOSStub_2c8f {
  strings:
    $key_2c8f = { 78 e7 [2] 0c ff [2] 4b fd [2] 0c ec [2] 42 e0 [2] 4e ea [2] 59 e1 [2] 42 af [2] 7f }

  condition:
    any of them
}