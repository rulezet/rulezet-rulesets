rule TTP_XOR_MULT_DOSStub_1093 {
  strings:
    $key_1093 = { 44 fb [2] 30 e3 [2] 77 e1 [2] 30 f0 [2] 7e fc [2] 72 f6 [2] 65 fd [2] 7e b3 [2] 43 }

  condition:
    any of them
}