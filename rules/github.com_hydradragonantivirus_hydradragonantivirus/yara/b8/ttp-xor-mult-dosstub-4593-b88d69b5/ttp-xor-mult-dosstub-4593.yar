rule TTP_XOR_MULT_DOSStub_4593 {
  strings:
    $key_4593 = { 11 fb [2] 65 e3 [2] 22 e1 [2] 65 f0 [2] 2b fc [2] 27 f6 [2] 30 fd [2] 2b b3 [2] 16 }

  condition:
    any of them
}