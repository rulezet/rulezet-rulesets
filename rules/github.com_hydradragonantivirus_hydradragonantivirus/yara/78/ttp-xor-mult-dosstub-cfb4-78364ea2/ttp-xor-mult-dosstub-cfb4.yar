rule TTP_XOR_MULT_DOSStub_cfb4 {
  strings:
    $key_cfb4 = { 9b dc [2] ef c4 [2] a8 c6 [2] ef d7 [2] a1 db [2] ad d1 [2] ba da [2] a1 94 [2] 9c }

  condition:
    any of them
}