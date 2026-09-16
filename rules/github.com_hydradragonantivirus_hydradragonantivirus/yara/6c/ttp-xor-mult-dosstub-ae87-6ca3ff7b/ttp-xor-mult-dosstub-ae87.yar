rule TTP_XOR_MULT_DOSStub_ae87 {
  strings:
    $key_ae87 = { fa ef [2] 8e f7 [2] c9 f5 [2] 8e e4 [2] c0 e8 [2] cc e2 [2] db e9 [2] c0 a7 [2] fd }

  condition:
    any of them
}