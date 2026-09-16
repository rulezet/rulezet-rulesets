rule TTP_XOR_MULT_DOSStub_558f {
  strings:
    $key_558f = { 01 e7 [2] 75 ff [2] 32 fd [2] 75 ec [2] 3b e0 [2] 37 ea [2] 20 e1 [2] 3b af [2] 06 }

  condition:
    any of them
}