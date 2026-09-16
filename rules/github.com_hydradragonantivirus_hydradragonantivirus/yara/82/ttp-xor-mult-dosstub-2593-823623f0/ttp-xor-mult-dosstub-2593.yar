rule TTP_XOR_MULT_DOSStub_2593 {
  strings:
    $key_2593 = { 71 fb [2] 05 e3 [2] 42 e1 [2] 05 f0 [2] 4b fc [2] 47 f6 [2] 50 fd [2] 4b b3 [2] 76 }

  condition:
    any of them
}