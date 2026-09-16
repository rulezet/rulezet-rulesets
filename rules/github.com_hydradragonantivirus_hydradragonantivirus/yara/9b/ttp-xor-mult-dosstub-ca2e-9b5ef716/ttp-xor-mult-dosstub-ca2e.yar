rule TTP_XOR_MULT_DOSStub_ca2e {
  strings:
    $key_ca2e = { 9e 46 [2] ea 5e [2] ad 5c [2] ea 4d [2] a4 41 [2] a8 4b [2] bf 40 [2] a4 0e [2] 99 }

  condition:
    any of them
}