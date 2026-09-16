rule TTP_XOR_MULT_DOSStub_cf4e {
  strings:
    $key_cf4e = { 9b 26 [2] ef 3e [2] a8 3c [2] ef 2d [2] a1 21 [2] ad 2b [2] ba 20 [2] a1 6e [2] 9c }

  condition:
    any of them
}