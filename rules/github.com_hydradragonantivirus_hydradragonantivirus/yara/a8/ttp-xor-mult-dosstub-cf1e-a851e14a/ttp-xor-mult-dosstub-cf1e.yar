rule TTP_XOR_MULT_DOSStub_cf1e {
  strings:
    $key_cf1e = { 9b 76 [2] ef 6e [2] a8 6c [2] ef 7d [2] a1 71 [2] ad 7b [2] ba 70 [2] a1 3e [2] 9c }

  condition:
    any of them
}