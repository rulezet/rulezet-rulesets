rule TTP_XOR_MULT_DOSStub_cf4c {
  strings:
    $key_cf4c = { 9b 24 [2] ef 3c [2] a8 3e [2] ef 2f [2] a1 23 [2] ad 29 [2] ba 22 [2] a1 6c [2] 9c }

  condition:
    any of them
}