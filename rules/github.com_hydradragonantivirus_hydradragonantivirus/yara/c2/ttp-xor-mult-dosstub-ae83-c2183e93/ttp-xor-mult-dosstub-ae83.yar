rule TTP_XOR_MULT_DOSStub_ae83 {
  strings:
    $key_ae83 = { fa eb [2] 8e f3 [2] c9 f1 [2] 8e e0 [2] c0 ec [2] cc e6 [2] db ed [2] c0 a3 [2] fd }

  condition:
    any of them
}