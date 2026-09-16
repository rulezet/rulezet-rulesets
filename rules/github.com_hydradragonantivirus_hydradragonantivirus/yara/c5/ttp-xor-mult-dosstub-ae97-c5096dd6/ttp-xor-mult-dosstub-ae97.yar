rule TTP_XOR_MULT_DOSStub_ae97 {
  strings:
    $key_ae97 = { fa ff [2] 8e e7 [2] c9 e5 [2] 8e f4 [2] c0 f8 [2] cc f2 [2] db f9 [2] c0 b7 [2] fd }

  condition:
    any of them
}