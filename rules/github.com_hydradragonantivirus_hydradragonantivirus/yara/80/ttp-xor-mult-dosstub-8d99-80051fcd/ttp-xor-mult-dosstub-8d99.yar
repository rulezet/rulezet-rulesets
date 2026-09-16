rule TTP_XOR_MULT_DOSStub_8d99 {
  strings:
    $key_8d99 = { d9 f1 [2] ad e9 [2] ea eb [2] ad fa [2] e3 f6 [2] ef fc [2] f8 f7 [2] e3 b9 [2] de }

  condition:
    any of them
}