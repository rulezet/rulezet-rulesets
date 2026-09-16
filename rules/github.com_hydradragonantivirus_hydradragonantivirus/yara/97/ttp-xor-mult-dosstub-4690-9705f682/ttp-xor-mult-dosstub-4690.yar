rule TTP_XOR_MULT_DOSStub_4690 {
  strings:
    $key_4690 = { 12 f8 [2] 66 e0 [2] 21 e2 [2] 66 f3 [2] 28 ff [2] 24 f5 [2] 33 fe [2] 28 b0 [2] 15 }

  condition:
    any of them
}