rule TTP_XOR_MULT_DOSStub_49ce {
  strings:
    $key_49ce = { 1d a6 [2] 69 be [2] 2e bc [2] 69 ad [2] 27 a1 [2] 2b ab [2] 3c a0 [2] 27 ee [2] 1a }

  condition:
    any of them
}