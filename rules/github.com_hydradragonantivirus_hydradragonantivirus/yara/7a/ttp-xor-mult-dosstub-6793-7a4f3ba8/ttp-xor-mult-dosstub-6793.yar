rule TTP_XOR_MULT_DOSStub_6793 {
  strings:
    $key_6793 = { 33 fb [2] 47 e3 [2] 00 e1 [2] 47 f0 [2] 09 fc [2] 05 f6 [2] 12 fd [2] 09 b3 [2] 34 }

  condition:
    any of them
}