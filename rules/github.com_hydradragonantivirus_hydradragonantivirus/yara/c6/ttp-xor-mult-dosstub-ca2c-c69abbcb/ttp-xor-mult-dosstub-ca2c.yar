rule TTP_XOR_MULT_DOSStub_ca2c {
  strings:
    $key_ca2c = { 9e 44 [2] ea 5c [2] ad 5e [2] ea 4f [2] a4 43 [2] a8 49 [2] bf 42 [2] a4 0c [2] 99 }

  condition:
    any of them
}