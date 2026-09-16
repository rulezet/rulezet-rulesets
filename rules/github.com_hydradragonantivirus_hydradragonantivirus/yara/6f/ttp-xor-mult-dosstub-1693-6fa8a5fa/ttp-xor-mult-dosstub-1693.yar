rule TTP_XOR_MULT_DOSStub_1693 {
  strings:
    $key_1693 = { 42 fb [2] 36 e3 [2] 71 e1 [2] 36 f0 [2] 78 fc [2] 74 f6 [2] 63 fd [2] 78 b3 [2] 45 }

  condition:
    any of them
}