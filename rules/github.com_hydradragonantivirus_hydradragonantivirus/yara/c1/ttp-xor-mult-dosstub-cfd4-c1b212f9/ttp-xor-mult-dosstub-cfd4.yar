rule TTP_XOR_MULT_DOSStub_cfd4 {
  strings:
    $key_cfd4 = { 9b bc [2] ef a4 [2] a8 a6 [2] ef b7 [2] a1 bb [2] ad b1 [2] ba ba [2] a1 f4 [2] 9c }

  condition:
    any of them
}