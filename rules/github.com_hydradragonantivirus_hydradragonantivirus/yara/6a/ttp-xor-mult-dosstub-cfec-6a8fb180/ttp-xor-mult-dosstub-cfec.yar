rule TTP_XOR_MULT_DOSStub_cfec {
  strings:
    $key_cfec = { 9b 84 [2] ef 9c [2] a8 9e [2] ef 8f [2] a1 83 [2] ad 89 [2] ba 82 [2] a1 cc [2] 9c }

  condition:
    any of them
}