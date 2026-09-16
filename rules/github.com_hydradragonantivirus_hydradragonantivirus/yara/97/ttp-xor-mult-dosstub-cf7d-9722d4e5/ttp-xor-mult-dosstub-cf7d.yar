rule TTP_XOR_MULT_DOSStub_cf7d {
  strings:
    $key_cf7d = { 9b 15 [2] ef 0d [2] a8 0f [2] ef 1e [2] a1 12 [2] ad 18 [2] ba 13 [2] a1 5d [2] 9c }

  condition:
    any of them
}