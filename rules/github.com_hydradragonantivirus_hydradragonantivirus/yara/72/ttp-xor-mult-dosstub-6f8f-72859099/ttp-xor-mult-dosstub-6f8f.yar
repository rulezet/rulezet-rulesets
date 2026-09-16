rule TTP_XOR_MULT_DOSStub_6f8f {
  strings:
    $key_6f8f = { 3b e7 [2] 4f ff [2] 08 fd [2] 4f ec [2] 01 e0 [2] 0d ea [2] 1a e1 [2] 01 af [2] 3c }

  condition:
    any of them
}