rule TTP_XOR_MULT_DOSStub_cf4d {
  strings:
    $key_cf4d = { 9b 25 [2] ef 3d [2] a8 3f [2] ef 2e [2] a1 22 [2] ad 28 [2] ba 23 [2] a1 6d [2] 9c }

  condition:
    any of them
}