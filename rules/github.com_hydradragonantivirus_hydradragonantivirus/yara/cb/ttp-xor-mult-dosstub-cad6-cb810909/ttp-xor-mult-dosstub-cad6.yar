rule TTP_XOR_MULT_DOSStub_cad6 {
  strings:
    $key_cad6 = { 9e be [2] ea a6 [2] ad a4 [2] ea b5 [2] a4 b9 [2] a8 b3 [2] bf b8 [2] a4 f6 [2] 99 }

  condition:
    any of them
}