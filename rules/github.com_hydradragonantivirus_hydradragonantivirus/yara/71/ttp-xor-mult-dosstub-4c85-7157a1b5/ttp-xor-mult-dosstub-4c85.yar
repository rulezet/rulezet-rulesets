rule TTP_XOR_MULT_DOSStub_4c85 {
  strings:
    $key_4c85 = { 18 ed [2] 6c f5 [2] 2b f7 [2] 6c e6 [2] 22 ea [2] 2e e0 [2] 39 eb [2] 22 a5 [2] 1f }

  condition:
    any of them
}