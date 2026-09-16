rule TTP_XOR_MULT_DOSStub_829e {
  strings:
    $key_829e = { d6 f6 [2] a2 ee [2] e5 ec [2] a2 fd [2] ec f1 [2] e0 fb [2] f7 f0 [2] ec be [2] d1 }

  condition:
    any of them
}