rule TTP_XOR_MULT_DOSStub_d789 {
  strings:
    $key_d789 = { 83 e1 [2] f7 f9 [2] b0 fb [2] f7 ea [2] b9 e6 [2] b5 ec [2] a2 e7 [2] b9 a9 [2] 84 }

  condition:
    any of them
}