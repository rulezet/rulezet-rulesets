rule TTP_XOR_MULT_DOSStub_caa3 {
  strings:
    $key_caa3 = { 9e cb [2] ea d3 [2] ad d1 [2] ea c0 [2] a4 cc [2] a8 c6 [2] bf cd [2] a4 83 [2] 99 }

  condition:
    any of them
}