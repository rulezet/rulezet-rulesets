rule TTP_XOR_MULT_DOSStub_5691 {
  strings:
    $key_5691 = { 02 f9 [2] 76 e1 [2] 31 e3 [2] 76 f2 [2] 38 fe [2] 34 f4 [2] 23 ff [2] 38 b1 [2] 05 }

  condition:
    any of them
}