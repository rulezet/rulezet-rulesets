rule TTP_XOR_MULT_DOSStub_94ad {
  strings:
    $key_94ad = { c0 c5 [2] b4 dd [2] f3 df [2] b4 ce [2] fa c2 [2] f6 c8 [2] e1 c3 [2] fa 8d [2] c7 }

  condition:
    any of them
}