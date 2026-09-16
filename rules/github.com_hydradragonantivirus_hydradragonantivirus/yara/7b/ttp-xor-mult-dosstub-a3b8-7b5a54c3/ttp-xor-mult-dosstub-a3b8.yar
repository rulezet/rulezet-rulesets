rule TTP_XOR_MULT_DOSStub_a3b8 {
  strings:
    $key_a3b8 = { f7 d0 [2] 83 c8 [2] c4 ca [2] 83 db [2] cd d7 [2] c1 dd [2] d6 d6 [2] cd 98 [2] f0 }

  condition:
    any of them
}