rule TTP_XOR_MULT_DOSStub_1c85 {
  strings:
    $key_1c85 = { 48 ed [2] 3c f5 [2] 7b f7 [2] 3c e6 [2] 72 ea [2] 7e e0 [2] 69 eb [2] 72 a5 [2] 4f }

  condition:
    any of them
}