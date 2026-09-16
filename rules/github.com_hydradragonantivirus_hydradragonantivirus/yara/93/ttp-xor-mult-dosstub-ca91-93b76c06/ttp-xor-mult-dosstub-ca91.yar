rule TTP_XOR_MULT_DOSStub_ca91 {
  strings:
    $key_ca91 = { 9e f9 [2] ea e1 [2] ad e3 [2] ea f2 [2] a4 fe [2] a8 f4 [2] bf ff [2] a4 b1 [2] 99 }

  condition:
    any of them
}