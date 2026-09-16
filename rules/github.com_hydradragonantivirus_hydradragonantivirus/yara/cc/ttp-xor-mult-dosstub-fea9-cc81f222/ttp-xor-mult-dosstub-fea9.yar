rule TTP_XOR_MULT_DOSStub_fea9 {
  strings:
    $key_fea9 = { aa c1 [2] de d9 [2] 99 db [2] de ca [2] 90 c6 [2] 9c cc [2] 8b c7 [2] 90 89 [2] ad }

  condition:
    any of them
}