rule TTP_XOR_MULT_DOSStub_97ad {
  strings:
    $key_97ad = { c3 c5 [2] b7 dd [2] f0 df [2] b7 ce [2] f9 c2 [2] f5 c8 [2] e2 c3 [2] f9 8d [2] c4 }

  condition:
    any of them
}