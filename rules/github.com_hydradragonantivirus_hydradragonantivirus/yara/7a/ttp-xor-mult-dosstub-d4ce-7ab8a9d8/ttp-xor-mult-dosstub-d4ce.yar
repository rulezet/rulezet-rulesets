rule TTP_XOR_MULT_DOSStub_d4ce {
  strings:
    $key_d4ce = { 80 a6 [2] f4 be [2] b3 bc [2] f4 ad [2] ba a1 [2] b6 ab [2] a1 a0 [2] ba ee [2] 87 }

  condition:
    any of them
}