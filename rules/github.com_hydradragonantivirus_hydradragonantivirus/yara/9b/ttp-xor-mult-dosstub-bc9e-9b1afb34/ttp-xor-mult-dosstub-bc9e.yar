rule TTP_XOR_MULT_DOSStub_bc9e {
  strings:
    $key_bc9e = { e8 f6 [2] 9c ee [2] db ec [2] 9c fd [2] d2 f1 [2] de fb [2] c9 f0 [2] d2 be [2] ef }

  condition:
    any of them
}