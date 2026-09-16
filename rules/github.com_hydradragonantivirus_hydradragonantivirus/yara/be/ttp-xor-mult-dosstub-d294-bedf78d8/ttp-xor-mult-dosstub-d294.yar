rule TTP_XOR_MULT_DOSStub_d294 {
  strings:
    $key_d294 = { 86 fc [2] f2 e4 [2] b5 e6 [2] f2 f7 [2] bc fb [2] b0 f1 [2] a7 fa [2] bc b4 [2] 81 }

  condition:
    any of them
}