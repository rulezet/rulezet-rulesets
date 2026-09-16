rule TTP_XOR_MULT_DOSStub_8b96 {
  strings:
    $key_8b96 = { df fe [2] ab e6 [2] ec e4 [2] ab f5 [2] e5 f9 [2] e9 f3 [2] fe f8 [2] e5 b6 [2] d8 }

  condition:
    any of them
}