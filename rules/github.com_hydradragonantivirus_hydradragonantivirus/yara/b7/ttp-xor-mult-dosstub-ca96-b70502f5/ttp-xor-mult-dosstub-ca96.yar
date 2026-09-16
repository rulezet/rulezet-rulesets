rule TTP_XOR_MULT_DOSStub_ca96 {
  strings:
    $key_ca96 = { 9e fe [2] ea e6 [2] ad e4 [2] ea f5 [2] a4 f9 [2] a8 f3 [2] bf f8 [2] a4 b6 [2] 99 }

  condition:
    any of them
}