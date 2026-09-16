rule TTP_XOR_MULT_DOSStub_5f8f {
  strings:
    $key_5f8f = { 0b e7 [2] 7f ff [2] 38 fd [2] 7f ec [2] 31 e0 [2] 3d ea [2] 2a e1 [2] 31 af [2] 0c }

  condition:
    any of them
}