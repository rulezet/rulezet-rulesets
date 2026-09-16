rule TTP_XOR_MULT_DOSStub_82b5 {
  strings:
    $key_82b5 = { d6 dd [2] a2 c5 [2] e5 c7 [2] a2 d6 [2] ec da [2] e0 d0 [2] f7 db [2] ec 95 [2] d1 }

  condition:
    any of them
}