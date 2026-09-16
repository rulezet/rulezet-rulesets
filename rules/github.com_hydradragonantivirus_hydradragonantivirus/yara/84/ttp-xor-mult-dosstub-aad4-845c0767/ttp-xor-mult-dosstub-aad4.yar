rule TTP_XOR_MULT_DOSStub_aad4 {
  strings:
    $key_aad4 = { fe bc [2] 8a a4 [2] cd a6 [2] 8a b7 [2] c4 bb [2] c8 b1 [2] df ba [2] c4 f4 [2] f9 }

  condition:
    any of them
}