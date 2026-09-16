rule TTP_XOR_MULT_DOSStub_1698 {
  strings:
    $key_1698 = { 42 f0 [2] 36 e8 [2] 71 ea [2] 36 fb [2] 78 f7 [2] 74 fd [2] 63 f6 [2] 78 b8 [2] 45 }

  condition:
    any of them
}