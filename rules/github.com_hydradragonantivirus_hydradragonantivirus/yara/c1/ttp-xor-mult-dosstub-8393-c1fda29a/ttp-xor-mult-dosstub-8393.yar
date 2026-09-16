rule TTP_XOR_MULT_DOSStub_8393 {
  strings:
    $key_8393 = { d7 fb [2] a3 e3 [2] e4 e1 [2] a3 f0 [2] ed fc [2] e1 f6 [2] f6 fd [2] ed b3 [2] d0 }

  condition:
    any of them
}