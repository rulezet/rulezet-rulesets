rule TTP_XOR_MULT_DOSStub_5793 {
  strings:
    $key_5793 = { 03 fb [2] 77 e3 [2] 30 e1 [2] 77 f0 [2] 39 fc [2] 35 f6 [2] 22 fd [2] 39 b3 [2] 04 }

  condition:
    any of them
}