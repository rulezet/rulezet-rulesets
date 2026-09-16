rule TTP_XOR_MULT_DOSStub_3390 {
  strings:
    $key_3390 = { 67 f8 [2] 13 e0 [2] 54 e2 [2] 13 f3 [2] 5d ff [2] 51 f5 [2] 46 fe [2] 5d b0 [2] 60 }

  condition:
    any of them
}