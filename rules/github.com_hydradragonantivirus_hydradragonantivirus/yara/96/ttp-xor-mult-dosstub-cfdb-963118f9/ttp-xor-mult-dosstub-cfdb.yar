rule TTP_XOR_MULT_DOSStub_cfdb {
  strings:
    $key_cfdb = { 9b b3 [2] ef ab [2] a8 a9 [2] ef b8 [2] a1 b4 [2] ad be [2] ba b5 [2] a1 fb [2] 9c }

  condition:
    any of them
}