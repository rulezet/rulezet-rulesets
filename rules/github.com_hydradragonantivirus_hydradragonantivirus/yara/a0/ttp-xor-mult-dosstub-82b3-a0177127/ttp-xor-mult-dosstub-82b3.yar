rule TTP_XOR_MULT_DOSStub_82b3 {
  strings:
    $key_82b3 = { d6 db [2] a2 c3 [2] e5 c1 [2] a2 d0 [2] ec dc [2] e0 d6 [2] f7 dd [2] ec 93 [2] d1 }

  condition:
    any of them
}