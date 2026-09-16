rule TTP_XOR_MULT_DOSStub_939e {
  strings:
    $key_939e = { c7 f6 [2] b3 ee [2] f4 ec [2] b3 fd [2] fd f1 [2] f1 fb [2] e6 f0 [2] fd be [2] c0 }

  condition:
    any of them
}