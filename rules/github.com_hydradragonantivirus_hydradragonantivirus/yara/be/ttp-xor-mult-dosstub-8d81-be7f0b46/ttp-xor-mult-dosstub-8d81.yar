rule TTP_XOR_MULT_DOSStub_8d81 {
  strings:
    $key_8d81 = { d9 e9 [2] ad f1 [2] ea f3 [2] ad e2 [2] e3 ee [2] ef e4 [2] f8 ef [2] e3 a1 [2] de }

  condition:
    any of them
}