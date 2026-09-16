rule TTP_XOR_MULT_DOSStub_ca45 {
  strings:
    $key_ca45 = { 9e 2d [2] ea 35 [2] ad 37 [2] ea 26 [2] a4 2a [2] a8 20 [2] bf 2b [2] a4 65 [2] 99 }

  condition:
    any of them
}