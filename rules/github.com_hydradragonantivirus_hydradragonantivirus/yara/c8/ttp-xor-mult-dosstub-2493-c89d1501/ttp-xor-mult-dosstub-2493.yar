rule TTP_XOR_MULT_DOSStub_2493 {
  strings:
    $key_2493 = { 70 fb [2] 04 e3 [2] 43 e1 [2] 04 f0 [2] 4a fc [2] 46 f6 [2] 51 fd [2] 4a b3 [2] 77 }

  condition:
    any of them
}