rule TTP_XOR_MULT_DOSStub_cffa {
  strings:
    $key_cffa = { 9b 92 [2] ef 8a [2] a8 88 [2] ef 99 [2] a1 95 [2] ad 9f [2] ba 94 [2] a1 da [2] 9c }

  condition:
    any of them
}