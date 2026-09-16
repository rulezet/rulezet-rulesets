rule TTP_XOR_MULT_DOSStub_1e8f {
  strings:
    $key_1e8f = { 4a e7 [2] 3e ff [2] 79 fd [2] 3e ec [2] 70 e0 [2] 7c ea [2] 6b e1 [2] 70 af [2] 4d }

  condition:
    any of them
}