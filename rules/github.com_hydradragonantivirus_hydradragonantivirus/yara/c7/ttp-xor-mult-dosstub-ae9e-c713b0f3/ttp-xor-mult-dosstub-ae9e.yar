rule TTP_XOR_MULT_DOSStub_ae9e {
  strings:
    $key_ae9e = { fa f6 [2] 8e ee [2] c9 ec [2] 8e fd [2] c0 f1 [2] cc fb [2] db f0 [2] c0 be [2] fd }

  condition:
    any of them
}