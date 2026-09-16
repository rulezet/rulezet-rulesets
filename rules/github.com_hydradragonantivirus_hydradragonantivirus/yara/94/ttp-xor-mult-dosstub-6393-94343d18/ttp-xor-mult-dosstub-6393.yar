rule TTP_XOR_MULT_DOSStub_6393 {
  strings:
    $key_6393 = { 37 fb [2] 43 e3 [2] 04 e1 [2] 43 f0 [2] 0d fc [2] 01 f6 [2] 16 fd [2] 0d b3 [2] 30 }

  condition:
    any of them
}