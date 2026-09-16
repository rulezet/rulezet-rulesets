rule TTP_XOR_MULT_DOSStub_e99e {
  strings:
    $key_e99e = { bd f6 [2] c9 ee [2] 8e ec [2] c9 fd [2] 87 f1 [2] 8b fb [2] 9c f0 [2] 87 be [2] ba }

  condition:
    any of them
}