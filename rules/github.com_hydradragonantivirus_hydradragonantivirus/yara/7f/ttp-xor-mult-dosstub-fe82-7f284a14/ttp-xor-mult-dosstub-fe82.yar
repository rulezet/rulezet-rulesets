rule TTP_XOR_MULT_DOSStub_fe82 {
  strings:
    $key_fe82 = { aa ea [2] de f2 [2] 99 f0 [2] de e1 [2] 90 ed [2] 9c e7 [2] 8b ec [2] 90 a2 [2] ad }

  condition:
    any of them
}