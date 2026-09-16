rule TTP_XOR_MULT_DOSStub_cf53 {
  strings:
    $key_cf53 = { 9b 3b [2] ef 23 [2] a8 21 [2] ef 30 [2] a1 3c [2] ad 36 [2] ba 3d [2] a1 73 [2] 9c }

  condition:
    any of them
}