rule TTP_XOR_MULT_DOSStub_ae81 {
  strings:
    $key_ae81 = { fa e9 [2] 8e f1 [2] c9 f3 [2] 8e e2 [2] c0 ee [2] cc e4 [2] db ef [2] c0 a1 [2] fd }

  condition:
    any of them
}