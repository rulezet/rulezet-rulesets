rule TTP_XOR_MULT_DOSStub_3793 {
  strings:
    $key_3793 = { 63 fb [2] 17 e3 [2] 50 e1 [2] 17 f0 [2] 59 fc [2] 55 f6 [2] 42 fd [2] 59 b3 [2] 64 }

  condition:
    any of them
}