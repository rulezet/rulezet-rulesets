rule TTP_XOR_MULT_DOSStub_cfd5 {
  strings:
    $key_cfd5 = { 9b bd [2] ef a5 [2] a8 a7 [2] ef b6 [2] a1 ba [2] ad b0 [2] ba bb [2] a1 f5 [2] 9c }

  condition:
    any of them
}