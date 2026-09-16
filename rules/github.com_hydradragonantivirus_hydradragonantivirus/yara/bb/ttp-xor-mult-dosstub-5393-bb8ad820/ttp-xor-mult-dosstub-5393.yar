rule TTP_XOR_MULT_DOSStub_5393 {
  strings:
    $key_5393 = { 07 fb [2] 73 e3 [2] 34 e1 [2] 73 f0 [2] 3d fc [2] 31 f6 [2] 26 fd [2] 3d b3 [2] 00 }

  condition:
    any of them
}