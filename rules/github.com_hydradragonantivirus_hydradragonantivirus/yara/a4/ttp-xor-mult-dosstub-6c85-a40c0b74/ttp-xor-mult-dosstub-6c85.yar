rule TTP_XOR_MULT_DOSStub_6c85 {
  strings:
    $key_6c85 = { 38 ed [2] 4c f5 [2] 0b f7 [2] 4c e6 [2] 02 ea [2] 0e e0 [2] 19 eb [2] 02 a5 [2] 3f }

  condition:
    any of them
}