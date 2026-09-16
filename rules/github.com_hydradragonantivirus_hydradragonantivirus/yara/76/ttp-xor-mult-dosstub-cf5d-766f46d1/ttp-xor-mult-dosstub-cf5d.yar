rule TTP_XOR_MULT_DOSStub_cf5d {
  strings:
    $key_cf5d = { 9b 35 [2] ef 2d [2] a8 2f [2] ef 3e [2] a1 32 [2] ad 38 [2] ba 33 [2] a1 7d [2] 9c }

  condition:
    any of them
}