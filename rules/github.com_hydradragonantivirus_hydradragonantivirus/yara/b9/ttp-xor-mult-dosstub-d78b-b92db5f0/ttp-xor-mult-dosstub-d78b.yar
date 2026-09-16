rule TTP_XOR_MULT_DOSStub_d78b {
  strings:
    $key_d78b = { 83 e3 [2] f7 fb [2] b0 f9 [2] f7 e8 [2] b9 e4 [2] b5 ee [2] a2 e5 [2] b9 ab [2] 84 }

  condition:
    any of them
}