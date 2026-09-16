rule TTP_XOR_MULT_DOSStub_aab4 {
  strings:
    $key_aab4 = { fe dc [2] 8a c4 [2] cd c6 [2] 8a d7 [2] c4 db [2] c8 d1 [2] df da [2] c4 94 [2] f9 }

  condition:
    any of them
}