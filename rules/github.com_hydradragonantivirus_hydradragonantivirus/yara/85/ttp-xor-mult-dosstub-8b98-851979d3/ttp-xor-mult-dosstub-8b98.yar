rule TTP_XOR_MULT_DOSStub_8b98 {
  strings:
    $key_8b98 = { df f0 [2] ab e8 [2] ec ea [2] ab fb [2] e5 f7 [2] e9 fd [2] fe f6 [2] e5 b8 [2] d8 }

  condition:
    any of them
}