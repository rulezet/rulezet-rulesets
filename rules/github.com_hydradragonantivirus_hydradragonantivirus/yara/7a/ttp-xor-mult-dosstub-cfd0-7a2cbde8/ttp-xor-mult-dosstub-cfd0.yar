rule TTP_XOR_MULT_DOSStub_cfd0 {
  strings:
    $key_cfd0 = { 9b b8 [2] ef a0 [2] a8 a2 [2] ef b3 [2] a1 bf [2] ad b5 [2] ba be [2] a1 f0 [2] 9c }

  condition:
    any of them
}