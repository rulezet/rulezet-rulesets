rule TTP_XOR_MULT_DOSStub_919e {
  strings:
    $key_919e = { c5 f6 [2] b1 ee [2] f6 ec [2] b1 fd [2] ff f1 [2] f3 fb [2] e4 f0 [2] ff be [2] c2 }

  condition:
    any of them
}