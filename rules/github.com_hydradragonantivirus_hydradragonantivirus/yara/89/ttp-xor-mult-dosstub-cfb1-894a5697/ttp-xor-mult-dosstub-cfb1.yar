rule TTP_XOR_MULT_DOSStub_cfb1 {
  strings:
    $key_cfb1 = { 9b d9 [2] ef c1 [2] a8 c3 [2] ef d2 [2] a1 de [2] ad d4 [2] ba df [2] a1 91 [2] 9c }

  condition:
    any of them
}