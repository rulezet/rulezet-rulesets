rule TTP_XOR_MULT_DOSStub_4c84 {
  strings:
    $key_4c84 = { 18 ec [2] 6c f4 [2] 2b f6 [2] 6c e7 [2] 22 eb [2] 2e e1 [2] 39 ea [2] 22 a4 [2] 1f }

  condition:
    any of them
}