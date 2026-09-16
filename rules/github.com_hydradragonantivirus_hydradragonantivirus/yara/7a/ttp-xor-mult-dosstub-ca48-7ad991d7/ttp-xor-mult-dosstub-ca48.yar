rule TTP_XOR_MULT_DOSStub_ca48 {
  strings:
    $key_ca48 = { 9e 20 [2] ea 38 [2] ad 3a [2] ea 2b [2] a4 27 [2] a8 2d [2] bf 26 [2] a4 68 [2] 99 }

  condition:
    any of them
}