rule TTP_XOR_MULT_DOSStub_5c84 {
  strings:
    $key_5c84 = { 08 ec [2] 7c f4 [2] 3b f6 [2] 7c e7 [2] 32 eb [2] 3e e1 [2] 29 ea [2] 32 a4 [2] 0f }

  condition:
    any of them
}