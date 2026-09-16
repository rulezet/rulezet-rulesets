rule TTP_XOR_MULT_DOSStub_cf6e {
  strings:
    $key_cf6e = { 9b 06 [2] ef 1e [2] a8 1c [2] ef 0d [2] a1 01 [2] ad 0b [2] ba 00 [2] a1 4e [2] 9c }

  condition:
    any of them
}