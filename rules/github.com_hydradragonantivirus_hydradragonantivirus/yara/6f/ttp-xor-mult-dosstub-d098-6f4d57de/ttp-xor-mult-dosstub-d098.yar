rule TTP_XOR_MULT_DOSStub_d098 {
  strings:
    $key_d098 = { 84 f0 [2] f0 e8 [2] b7 ea [2] f0 fb [2] be f7 [2] b2 fd [2] a5 f6 [2] be b8 [2] 83 }

  condition:
    any of them
}