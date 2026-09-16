rule TTP_XOR_MULT_DOSStub_d089 {
  strings:
    $key_d089 = { 84 e1 [2] f0 f9 [2] b7 fb [2] f0 ea [2] be e6 [2] b2 ec [2] a5 e7 [2] be a9 [2] 83 }

  condition:
    any of them
}