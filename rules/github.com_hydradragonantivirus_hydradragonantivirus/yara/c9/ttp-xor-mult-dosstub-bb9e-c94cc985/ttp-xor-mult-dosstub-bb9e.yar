rule TTP_XOR_MULT_DOSStub_bb9e {
  strings:
    $key_bb9e = { ef f6 [2] 9b ee [2] dc ec [2] 9b fd [2] d5 f1 [2] d9 fb [2] ce f0 [2] d5 be [2] e8 }

  condition:
    any of them
}