rule TTP_XOR_MULT_DOSStub_7693 {
  strings:
    $key_7693 = { 22 fb [2] 56 e3 [2] 11 e1 [2] 56 f0 [2] 18 fc [2] 14 f6 [2] 03 fd [2] 18 b3 [2] 25 }

  condition:
    any of them
}