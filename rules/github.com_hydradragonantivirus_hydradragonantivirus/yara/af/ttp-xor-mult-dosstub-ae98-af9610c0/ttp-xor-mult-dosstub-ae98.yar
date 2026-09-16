rule TTP_XOR_MULT_DOSStub_ae98 {
  strings:
    $key_ae98 = { fa f0 [2] 8e e8 [2] c9 ea [2] 8e fb [2] c0 f7 [2] cc fd [2] db f6 [2] c0 b8 [2] fd }

  condition:
    any of them
}