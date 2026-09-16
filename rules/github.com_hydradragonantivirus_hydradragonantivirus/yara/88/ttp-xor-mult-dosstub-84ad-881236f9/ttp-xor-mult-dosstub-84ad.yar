rule TTP_XOR_MULT_DOSStub_84ad {
  strings:
    $key_84ad = { d0 c5 [2] a4 dd [2] e3 df [2] a4 ce [2] ea c2 [2] e6 c8 [2] f1 c3 [2] ea 8d [2] d7 }

  condition:
    any of them
}