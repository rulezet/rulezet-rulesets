rule TTP_XOR_MULT_DOSStub_ca58 {
  strings:
    $key_ca58 = { 9e 30 [2] ea 28 [2] ad 2a [2] ea 3b [2] a4 37 [2] a8 3d [2] bf 36 [2] a4 78 [2] 99 }

  condition:
    any of them
}