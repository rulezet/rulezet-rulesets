rule TTP_XOR_MULT_DOSStub_ae96 {
  strings:
    $key_ae96 = { fa fe [2] 8e e6 [2] c9 e4 [2] 8e f5 [2] c0 f9 [2] cc f3 [2] db f8 [2] c0 b6 [2] fd }

  condition:
    any of them
}