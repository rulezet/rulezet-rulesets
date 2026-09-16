rule TTP_XOR_MULT_DOSStub_ee8f {
  strings:
    $key_ee8f = { ba e7 [2] ce ff [2] 89 fd [2] ce ec [2] 80 e0 [2] 8c ea [2] 9b e1 [2] 80 af [2] bd }

  condition:
    any of them
}