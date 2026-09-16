rule TTP_XOR_MULT_DOSStub_5490 {
  strings:
    $key_5490 = { 00 f8 [2] 74 e0 [2] 33 e2 [2] 74 f3 [2] 3a ff [2] 36 f5 [2] 21 fe [2] 3a b0 [2] 07 }

  condition:
    any of them
}