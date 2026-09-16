rule TTP_XOR_MULT_DOSStub_849e {
  strings:
    $key_849e = { d0 f6 [2] a4 ee [2] e3 ec [2] a4 fd [2] ea f1 [2] e6 fb [2] f1 f0 [2] ea be [2] d7 }

  condition:
    any of them
}