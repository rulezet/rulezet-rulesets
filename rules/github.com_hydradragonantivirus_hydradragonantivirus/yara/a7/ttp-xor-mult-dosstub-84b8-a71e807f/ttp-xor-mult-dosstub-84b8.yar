rule TTP_XOR_MULT_DOSStub_84b8 {
  strings:
    $key_84b8 = { d0 d0 [2] a4 c8 [2] e3 ca [2] a4 db [2] ea d7 [2] e6 dd [2] f1 d6 [2] ea 98 [2] d7 }

  condition:
    any of them
}