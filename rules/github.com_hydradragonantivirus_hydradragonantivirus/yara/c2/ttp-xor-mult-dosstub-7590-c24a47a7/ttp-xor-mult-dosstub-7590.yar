rule TTP_XOR_MULT_DOSStub_7590 {
  strings:
    $key_7590 = { 21 f8 [2] 55 e0 [2] 12 e2 [2] 55 f3 [2] 1b ff [2] 17 f5 [2] 00 fe [2] 1b b0 [2] 26 }

  condition:
    any of them
}