rule TTP_XOR_MULT_DOSStub_4490 {
  strings:
    $key_4490 = { 10 f8 [2] 64 e0 [2] 23 e2 [2] 64 f3 [2] 2a ff [2] 26 f5 [2] 31 fe [2] 2a b0 [2] 17 }

  condition:
    any of them
}