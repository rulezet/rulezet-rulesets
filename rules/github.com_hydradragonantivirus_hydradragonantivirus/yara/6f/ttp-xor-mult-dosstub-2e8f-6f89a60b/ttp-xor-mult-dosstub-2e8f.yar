rule TTP_XOR_MULT_DOSStub_2e8f {
  strings:
    $key_2e8f = { 7a e7 [2] 0e ff [2] 49 fd [2] 0e ec [2] 40 e0 [2] 4c ea [2] 5b e1 [2] 40 af [2] 7d }

  condition:
    any of them
}