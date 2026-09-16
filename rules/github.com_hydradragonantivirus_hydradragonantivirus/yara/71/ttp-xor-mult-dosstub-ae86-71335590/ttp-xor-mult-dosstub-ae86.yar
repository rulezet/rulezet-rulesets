rule TTP_XOR_MULT_DOSStub_ae86 {
  strings:
    $key_ae86 = { fa ee [2] 8e f6 [2] c9 f4 [2] 8e e5 [2] c0 e9 [2] cc e3 [2] db e8 [2] c0 a6 [2] fd }

  condition:
    any of them
}