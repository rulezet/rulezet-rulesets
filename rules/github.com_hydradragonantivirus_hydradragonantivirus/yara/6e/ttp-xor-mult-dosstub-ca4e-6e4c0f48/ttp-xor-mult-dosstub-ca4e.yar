rule TTP_XOR_MULT_DOSStub_ca4e {
  strings:
    $key_ca4e = { 9e 26 [2] ea 3e [2] ad 3c [2] ea 2d [2] a4 21 [2] a8 2b [2] bf 20 [2] a4 6e [2] 99 }

  condition:
    any of them
}