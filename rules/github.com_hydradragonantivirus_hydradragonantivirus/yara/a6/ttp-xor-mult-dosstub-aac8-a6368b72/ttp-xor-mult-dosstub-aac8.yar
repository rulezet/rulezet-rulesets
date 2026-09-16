rule TTP_XOR_MULT_DOSStub_aac8 {
  strings:
    $key_aac8 = { fe a0 [2] 8a b8 [2] cd ba [2] 8a ab [2] c4 a7 [2] c8 ad [2] df a6 [2] c4 e8 [2] f9 }

  condition:
    any of them
}