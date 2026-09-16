rule TTP_XOR_MULT_DOSStub_d7ce {
  strings:
    $key_d7ce = { 83 a6 [2] f7 be [2] b0 bc [2] f7 ad [2] b9 a1 [2] b5 ab [2] a2 a0 [2] b9 ee [2] 84 }

  condition:
    any of them
}