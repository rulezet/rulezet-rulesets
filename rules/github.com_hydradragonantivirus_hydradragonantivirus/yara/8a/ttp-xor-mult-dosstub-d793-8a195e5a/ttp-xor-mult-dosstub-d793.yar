rule TTP_XOR_MULT_DOSStub_d793 {
  strings:
    $key_d793 = { 83 fb [2] f7 e3 [2] b0 e1 [2] f7 f0 [2] b9 fc [2] b5 f6 [2] a2 fd [2] b9 b3 [2] 84 }

  condition:
    any of them
}