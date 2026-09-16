rule TTP_XOR_MULT_DOSStub_ce8f {
  strings:
    $key_ce8f = { 9a e7 [2] ee ff [2] a9 fd [2] ee ec [2] a0 e0 [2] ac ea [2] bb e1 [2] a0 af [2] 9d }

  condition:
    any of them
}