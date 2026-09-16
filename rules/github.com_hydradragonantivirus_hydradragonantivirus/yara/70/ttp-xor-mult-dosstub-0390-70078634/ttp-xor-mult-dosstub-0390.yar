rule TTP_XOR_MULT_DOSStub_0390 {
  strings:
    $key_0390 = { 57 f8 [2] 23 e0 [2] 64 e2 [2] 23 f3 [2] 6d ff [2] 61 f5 [2] 76 fe [2] 6d b0 [2] 50 }

  condition:
    any of them
}