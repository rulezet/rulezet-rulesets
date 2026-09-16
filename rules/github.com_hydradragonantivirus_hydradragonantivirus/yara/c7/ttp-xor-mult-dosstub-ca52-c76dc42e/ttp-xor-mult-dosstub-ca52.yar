rule TTP_XOR_MULT_DOSStub_ca52 {
  strings:
    $key_ca52 = { 9e 3a [2] ea 22 [2] ad 20 [2] ea 31 [2] a4 3d [2] a8 37 [2] bf 3c [2] a4 72 [2] 99 }

  condition:
    any of them
}