rule TTP_XOR_MULT_DOSStub_ca68 {
  strings:
    $key_ca68 = { 9e 00 [2] ea 18 [2] ad 1a [2] ea 0b [2] a4 07 [2] a8 0d [2] bf 06 [2] a4 48 [2] 99 }

  condition:
    any of them
}