rule TTP_XOR_MULT_DOSStub_d093 {
  strings:
    $key_d093 = { 84 fb [2] f0 e3 [2] b7 e1 [2] f0 f0 [2] be fc [2] b2 f6 [2] a5 fd [2] be b3 [2] 83 }

  condition:
    any of them
}