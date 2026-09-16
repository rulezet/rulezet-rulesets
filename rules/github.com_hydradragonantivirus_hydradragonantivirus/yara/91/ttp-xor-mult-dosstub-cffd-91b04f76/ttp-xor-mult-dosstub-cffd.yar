rule TTP_XOR_MULT_DOSStub_cffd {
  strings:
    $key_cffd = { 9b 95 [2] ef 8d [2] a8 8f [2] ef 9e [2] a1 92 [2] ad 98 [2] ba 93 [2] a1 dd [2] 9c }

  condition:
    any of them
}