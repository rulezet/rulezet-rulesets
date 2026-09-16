rule TTP_XOR_MULT_DOSStub_7086 {
  strings:
    $key_7086 = { 24 ee [2] 50 f6 [2] 17 f4 [2] 50 e5 [2] 1e e9 [2] 12 e3 [2] 05 e8 [2] 1e a6 [2] 23 }

  condition:
    any of them
}