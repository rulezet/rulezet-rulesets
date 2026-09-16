rule TTP_XOR_MULT_DOSStub_85ab {
  strings:
    $key_85ab = { d1 c3 [2] a5 db [2] e2 d9 [2] a5 c8 [2] eb c4 [2] e7 ce [2] f0 c5 [2] eb 8b [2] d6 }

  condition:
    any of them
}