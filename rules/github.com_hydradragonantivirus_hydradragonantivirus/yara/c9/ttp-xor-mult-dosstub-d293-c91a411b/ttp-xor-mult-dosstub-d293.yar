rule TTP_XOR_MULT_DOSStub_d293 {
  strings:
    $key_d293 = { 86 fb [2] f2 e3 [2] b5 e1 [2] f2 f0 [2] bc fc [2] b0 f6 [2] a7 fd [2] bc b3 [2] 81 }

  condition:
    any of them
}