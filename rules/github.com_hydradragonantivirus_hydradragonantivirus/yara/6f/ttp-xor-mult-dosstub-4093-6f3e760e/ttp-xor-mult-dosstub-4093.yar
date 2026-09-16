rule TTP_XOR_MULT_DOSStub_4093 {
  strings:
    $key_4093 = { 14 fb [2] 60 e3 [2] 27 e1 [2] 60 f0 [2] 2e fc [2] 22 f6 [2] 35 fd [2] 2e b3 [2] 13 }

  condition:
    any of them
}