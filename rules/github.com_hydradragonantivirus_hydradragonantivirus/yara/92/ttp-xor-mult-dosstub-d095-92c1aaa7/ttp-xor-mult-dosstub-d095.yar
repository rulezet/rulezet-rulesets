rule TTP_XOR_MULT_DOSStub_d095 {
  strings:
    $key_d095 = { 84 fd [2] f0 e5 [2] b7 e7 [2] f0 f6 [2] be fa [2] b2 f0 [2] a5 fb [2] be b5 [2] 83 }

  condition:
    any of them
}