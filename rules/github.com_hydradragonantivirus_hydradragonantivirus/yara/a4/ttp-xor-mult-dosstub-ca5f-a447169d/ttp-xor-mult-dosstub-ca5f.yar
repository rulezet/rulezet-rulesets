rule TTP_XOR_MULT_DOSStub_ca5f {
  strings:
    $key_ca5f = { 9e 37 [2] ea 2f [2] ad 2d [2] ea 3c [2] a4 30 [2] a8 3a [2] bf 31 [2] a4 7f [2] 99 }

  condition:
    any of them
}