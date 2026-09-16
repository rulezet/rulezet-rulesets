rule TTP_XOR_MULT_DOSStub_cfb2 {
  strings:
    $key_cfb2 = { 9b da [2] ef c2 [2] a8 c0 [2] ef d1 [2] a1 dd [2] ad d7 [2] ba dc [2] a1 92 [2] 9c }

  condition:
    any of them
}