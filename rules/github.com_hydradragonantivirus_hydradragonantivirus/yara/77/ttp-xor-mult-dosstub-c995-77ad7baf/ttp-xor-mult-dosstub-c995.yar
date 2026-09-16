rule TTP_XOR_MULT_DOSStub_c995 {
  strings:
    $key_c995 = { 9d fd [2] e9 e5 [2] ae e7 [2] e9 f6 [2] a7 fa [2] ab f0 [2] bc fb [2] a7 b5 [2] 9a }

  condition:
    any of them
}