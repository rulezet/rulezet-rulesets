rule TTP_XOR_MULT_DOSStub_82ab {
  strings:
    $key_82ab = { d6 c3 [2] a2 db [2] e5 d9 [2] a2 c8 [2] ec c4 [2] e0 ce [2] f7 c5 [2] ec 8b [2] d1 }

  condition:
    any of them
}