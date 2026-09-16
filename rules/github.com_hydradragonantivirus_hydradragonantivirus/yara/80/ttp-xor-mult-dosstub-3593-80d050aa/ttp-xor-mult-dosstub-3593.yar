rule TTP_XOR_MULT_DOSStub_3593 {
  strings:
    $key_3593 = { 61 fb [2] 15 e3 [2] 52 e1 [2] 15 f0 [2] 5b fc [2] 57 f6 [2] 40 fd [2] 5b b3 [2] 66 }

  condition:
    any of them
}