rule TTP_XOR_MULT_DOSStub_6e8f {
  strings:
    $key_6e8f = { 3a e7 [2] 4e ff [2] 09 fd [2] 4e ec [2] 00 e0 [2] 0c ea [2] 1b e1 [2] 00 af [2] 3d }

  condition:
    any of them
}