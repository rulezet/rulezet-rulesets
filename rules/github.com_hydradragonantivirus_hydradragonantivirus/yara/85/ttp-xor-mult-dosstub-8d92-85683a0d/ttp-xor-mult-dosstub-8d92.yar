rule TTP_XOR_MULT_DOSStub_8d92 {
  strings:
    $key_8d92 = { d9 fa [2] ad e2 [2] ea e0 [2] ad f1 [2] e3 fd [2] ef f7 [2] f8 fc [2] e3 b2 [2] de }

  condition:
    any of them
}