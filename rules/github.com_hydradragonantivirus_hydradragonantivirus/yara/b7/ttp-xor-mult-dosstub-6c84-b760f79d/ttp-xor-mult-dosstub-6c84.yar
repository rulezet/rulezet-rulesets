rule TTP_XOR_MULT_DOSStub_6c84 {
  strings:
    $key_6c84 = { 38 ec [2] 4c f4 [2] 0b f6 [2] 4c e7 [2] 02 eb [2] 0e e1 [2] 19 ea [2] 02 a4 [2] 3f }

  condition:
    any of them
}