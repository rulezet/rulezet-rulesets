rule TTP_XOR_MULT_DOSStub_7490 {
  strings:
    $key_7490 = { 20 f8 [2] 54 e0 [2] 13 e2 [2] 54 f3 [2] 1a ff [2] 16 f5 [2] 01 fe [2] 1a b0 [2] 27 }

  condition:
    any of them
}