rule TTP_XOR_MULT_DOSStub_ca72 {
  strings:
    $key_ca72 = { 9e 1a [2] ea 02 [2] ad 00 [2] ea 11 [2] a4 1d [2] a8 17 [2] bf 1c [2] a4 52 [2] 99 }

  condition:
    any of them
}