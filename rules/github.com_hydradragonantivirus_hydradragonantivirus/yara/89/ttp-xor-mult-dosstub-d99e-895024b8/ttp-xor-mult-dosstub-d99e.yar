rule TTP_XOR_MULT_DOSStub_d99e {
  strings:
    $key_d99e = { 8d f6 [2] f9 ee [2] be ec [2] f9 fd [2] b7 f1 [2] bb fb [2] ac f0 [2] b7 be [2] 8a }

  condition:
    any of them
}