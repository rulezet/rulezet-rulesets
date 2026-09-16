rule TTP_XOR_MULT_DOSStub_5590 {
  strings:
    $key_5590 = { 01 f8 [2] 75 e0 [2] 32 e2 [2] 75 f3 [2] 3b ff [2] 37 f5 [2] 20 fe [2] 3b b0 [2] 06 }

  condition:
    any of them
}