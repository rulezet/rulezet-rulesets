rule TTP_XOR_MULT_DOSStub_a193 {
  strings:
    $key_a193 = { f5 fb [2] 81 e3 [2] c6 e1 [2] 81 f0 [2] cf fc [2] c3 f6 [2] d4 fd [2] cf b3 [2] f2 }

  condition:
    any of them
}