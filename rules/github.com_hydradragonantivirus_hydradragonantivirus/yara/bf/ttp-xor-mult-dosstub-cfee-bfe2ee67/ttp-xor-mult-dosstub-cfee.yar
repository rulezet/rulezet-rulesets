rule TTP_XOR_MULT_DOSStub_cfee {
  strings:
    $key_cfee = { 9b 86 [2] ef 9e [2] a8 9c [2] ef 8d [2] a1 81 [2] ad 8b [2] ba 80 [2] a1 ce [2] 9c }

  condition:
    any of them
}