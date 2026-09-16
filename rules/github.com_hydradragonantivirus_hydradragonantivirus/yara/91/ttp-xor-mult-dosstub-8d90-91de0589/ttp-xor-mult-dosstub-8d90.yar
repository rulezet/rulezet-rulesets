rule TTP_XOR_MULT_DOSStub_8d90 {
  strings:
    $key_8d90 = { d9 f8 [2] ad e0 [2] ea e2 [2] ad f3 [2] e3 ff [2] ef f5 [2] f8 fe [2] e3 b0 [2] de }

  condition:
    any of them
}