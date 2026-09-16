rule TTP_XOR_MULT_DOSStub_90ad {
  strings:
    $key_90ad = { c4 c5 [2] b0 dd [2] f7 df [2] b0 ce [2] fe c2 [2] f2 c8 [2] e5 c3 [2] fe 8d [2] c3 }

  condition:
    any of them
}