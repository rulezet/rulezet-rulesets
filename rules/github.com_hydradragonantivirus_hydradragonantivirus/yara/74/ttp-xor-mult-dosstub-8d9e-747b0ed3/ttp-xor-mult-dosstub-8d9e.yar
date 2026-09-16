rule TTP_XOR_MULT_DOSStub_8d9e {
  strings:
    $key_8d9e = { d9 f6 [2] ad ee [2] ea ec [2] ad fd [2] e3 f1 [2] ef fb [2] f8 f0 [2] e3 be [2] de }

  condition:
    any of them
}