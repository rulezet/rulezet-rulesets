rule TTP_XOR_MULT_DOSStub_839e {
  strings:
    $key_839e = { d7 f6 [2] a3 ee [2] e4 ec [2] a3 fd [2] ed f1 [2] e1 fb [2] f6 f0 [2] ed be [2] d0 }

  condition:
    any of them
}