rule TTP_XOR_MULT_DOSStub_d295 {
  strings:
    $key_d295 = { 86 fd [2] f2 e5 [2] b5 e7 [2] f2 f6 [2] bc fa [2] b0 f0 [2] a7 fb [2] bc b5 [2] 81 }

  condition:
    any of them
}