rule TTP_XOR_MULT_DOSStub_7691 {
  strings:
    $key_7691 = { 22 f9 [2] 56 e1 [2] 11 e3 [2] 56 f2 [2] 18 fe [2] 14 f4 [2] 03 ff [2] 18 b1 [2] 25 }

  condition:
    any of them
}