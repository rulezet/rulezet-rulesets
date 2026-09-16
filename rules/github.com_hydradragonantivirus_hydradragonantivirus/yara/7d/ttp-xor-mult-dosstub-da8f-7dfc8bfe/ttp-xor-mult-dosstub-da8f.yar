rule TTP_XOR_MULT_DOSStub_da8f {
  strings:
    $key_da8f = { 8e e7 [2] fa ff [2] bd fd [2] fa ec [2] b4 e0 [2] b8 ea [2] af e1 [2] b4 af [2] 89 }

  condition:
    any of them
}