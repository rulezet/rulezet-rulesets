rule TTP_XOR_MULT_DOSStub_d08b {
  strings:
    $key_d08b = { 84 e3 [2] f0 fb [2] b7 f9 [2] f0 e8 [2] be e4 [2] b2 ee [2] a5 e5 [2] be ab [2] 83 }

  condition:
    any of them
}