rule TTP_XOR_MULT_DOSStub_ca59 {
  strings:
    $key_ca59 = { 9e 31 [2] ea 29 [2] ad 2b [2] ea 3a [2] a4 36 [2] a8 3c [2] bf 37 [2] a4 79 [2] 99 }

  condition:
    any of them
}