rule TTP_XOR_MULT_DOSStub_3590 {
  strings:
    $key_3590 = { 61 f8 [2] 15 e0 [2] 52 e2 [2] 15 f3 [2] 5b ff [2] 57 f5 [2] 40 fe [2] 5b b0 [2] 66 }

  condition:
    any of them
}