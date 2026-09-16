rule TTP_XOR_MULT_DOSStub_c88f {
  strings:
    $key_c88f = { 9c e7 [2] e8 ff [2] af fd [2] e8 ec [2] a6 e0 [2] aa ea [2] bd e1 [2] a6 af [2] 9b }

  condition:
    any of them
}