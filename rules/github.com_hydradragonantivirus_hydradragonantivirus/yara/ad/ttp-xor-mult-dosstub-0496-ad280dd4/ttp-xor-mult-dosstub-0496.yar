rule TTP_XOR_MULT_DOSStub_0496 {
  strings:
    $key_0496 = { 50 fe [2] 24 e6 [2] 63 e4 [2] 24 f5 [2] 6a f9 [2] 66 f3 [2] 71 f8 [2] 6a b6 [2] 57 }

  condition:
    any of them
}