rule TTP_XOR_MULT_DOSStub_4393 {
  strings:
    $key_4393 = { 17 fb [2] 63 e3 [2] 24 e1 [2] 63 f0 [2] 2d fc [2] 21 f6 [2] 36 fd [2] 2d b3 [2] 10 }

  condition:
    any of them
}