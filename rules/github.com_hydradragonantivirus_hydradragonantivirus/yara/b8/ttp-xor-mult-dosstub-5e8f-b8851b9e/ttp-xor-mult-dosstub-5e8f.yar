rule TTP_XOR_MULT_DOSStub_5e8f {
  strings:
    $key_5e8f = { 0a e7 [2] 7e ff [2] 39 fd [2] 7e ec [2] 30 e0 [2] 3c ea [2] 2b e1 [2] 30 af [2] 0d }

  condition:
    any of them
}