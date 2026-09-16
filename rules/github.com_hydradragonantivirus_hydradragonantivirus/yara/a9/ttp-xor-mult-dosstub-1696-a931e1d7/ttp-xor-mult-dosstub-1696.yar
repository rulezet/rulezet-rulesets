rule TTP_XOR_MULT_DOSStub_1696 {
  strings:
    $key_1696 = { 42 fe [2] 36 e6 [2] 71 e4 [2] 36 f5 [2] 78 f9 [2] 74 f3 [2] 63 f8 [2] 78 b6 [2] 45 }

  condition:
    any of them
}