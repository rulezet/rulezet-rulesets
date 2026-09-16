rule TTP_XOR_MULT_DOSStub_928b {
  strings:
    $key_928b = { c6 e3 [2] b2 fb [2] f5 f9 [2] b2 e8 [2] fc e4 [2] f0 ee [2] e7 e5 [2] fc ab [2] c1 }

  condition:
    any of them
}