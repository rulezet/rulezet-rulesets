rule TTP_XOR_MULT_DOSStub_7f8f {
  strings:
    $key_7f8f = { 2b e7 [2] 5f ff [2] 18 fd [2] 5f ec [2] 11 e0 [2] 1d ea [2] 0a e1 [2] 11 af [2] 2c }

  condition:
    any of them
}