rule TTP_XOR_MULT_DOSStub_f99e {
  strings:
    $key_f99e = { ad f6 [2] d9 ee [2] 9e ec [2] d9 fd [2] 97 f1 [2] 9b fb [2] 8c f0 [2] 97 be [2] aa }

  condition:
    any of them
}