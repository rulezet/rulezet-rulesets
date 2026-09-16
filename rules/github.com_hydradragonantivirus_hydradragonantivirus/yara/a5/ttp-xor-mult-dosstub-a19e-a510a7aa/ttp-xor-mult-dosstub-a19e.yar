rule TTP_XOR_MULT_DOSStub_a19e {
  strings:
    $key_a19e = { f5 f6 [2] 81 ee [2] c6 ec [2] 81 fd [2] cf f1 [2] c3 fb [2] d4 f0 [2] cf be [2] f2 }

  condition:
    any of them
}