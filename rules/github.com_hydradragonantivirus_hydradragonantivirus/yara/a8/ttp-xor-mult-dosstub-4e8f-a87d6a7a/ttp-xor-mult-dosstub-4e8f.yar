rule TTP_XOR_MULT_DOSStub_4e8f {
  strings:
    $key_4e8f = { 1a e7 [2] 6e ff [2] 29 fd [2] 6e ec [2] 20 e0 [2] 2c ea [2] 3b e1 [2] 20 af [2] 1d }

  condition:
    any of them
}