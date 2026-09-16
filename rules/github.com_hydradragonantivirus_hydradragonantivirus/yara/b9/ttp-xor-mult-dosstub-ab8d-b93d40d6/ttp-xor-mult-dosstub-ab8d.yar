rule TTP_XOR_MULT_DOSStub_ab8d {
  strings:
    $key_ab8d = { ff e5 [2] 8b fd [2] cc ff [2] 8b ee [2] c5 e2 [2] c9 e8 [2] de e3 [2] c5 ad [2] f8 }

  condition:
    any of them
}