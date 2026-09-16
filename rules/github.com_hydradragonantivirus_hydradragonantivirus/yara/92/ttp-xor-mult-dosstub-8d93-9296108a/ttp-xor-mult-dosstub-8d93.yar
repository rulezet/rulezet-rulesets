rule TTP_XOR_MULT_DOSStub_8d93 {
  strings:
    $key_8d93 = { d9 fb [2] ad e3 [2] ea e1 [2] ad f0 [2] e3 fc [2] ef f6 [2] f8 fd [2] e3 b3 [2] de }

  condition:
    any of them
}