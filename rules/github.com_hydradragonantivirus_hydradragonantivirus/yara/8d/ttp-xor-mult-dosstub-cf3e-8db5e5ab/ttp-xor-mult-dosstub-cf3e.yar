rule TTP_XOR_MULT_DOSStub_cf3e {
  strings:
    $key_cf3e = { 9b 56 [2] ef 4e [2] a8 4c [2] ef 5d [2] a1 51 [2] ad 5b [2] ba 50 [2] a1 1e [2] 9c }

  condition:
    any of them
}