rule TTP_XOR_MULT_DOSStub_5093 {
  strings:
    $key_5093 = { 04 fb [2] 70 e3 [2] 37 e1 [2] 70 f0 [2] 3e fc [2] 32 f6 [2] 25 fd [2] 3e b3 [2] 03 }

  condition:
    any of them
}