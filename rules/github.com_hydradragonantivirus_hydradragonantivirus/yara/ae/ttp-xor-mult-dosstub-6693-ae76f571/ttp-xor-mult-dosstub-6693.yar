rule TTP_XOR_MULT_DOSStub_6693 {
  strings:
    $key_6693 = { 32 fb [2] 46 e3 [2] 01 e1 [2] 46 f0 [2] 08 fc [2] 04 f6 [2] 13 fd [2] 08 b3 [2] 35 }

  condition:
    any of them
}