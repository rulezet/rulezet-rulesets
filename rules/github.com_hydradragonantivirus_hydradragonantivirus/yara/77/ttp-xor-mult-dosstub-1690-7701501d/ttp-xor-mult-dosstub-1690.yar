rule TTP_XOR_MULT_DOSStub_1690 {
  strings:
    $key_1690 = { 42 f8 [2] 36 e0 [2] 71 e2 [2] 36 f3 [2] 78 ff [2] 74 f5 [2] 63 fe [2] 78 b0 [2] 45 }

  condition:
    any of them
}