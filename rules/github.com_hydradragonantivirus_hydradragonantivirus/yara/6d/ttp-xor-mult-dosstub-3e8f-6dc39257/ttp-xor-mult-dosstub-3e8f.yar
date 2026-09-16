rule TTP_XOR_MULT_DOSStub_3e8f {
  strings:
    $key_3e8f = { 6a e7 [2] 1e ff [2] 59 fd [2] 1e ec [2] 50 e0 [2] 5c ea [2] 4b e1 [2] 50 af [2] 6d }

  condition:
    any of them
}