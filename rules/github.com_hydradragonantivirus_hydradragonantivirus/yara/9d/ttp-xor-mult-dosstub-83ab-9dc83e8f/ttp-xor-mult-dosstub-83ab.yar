rule TTP_XOR_MULT_DOSStub_83ab {
  strings:
    $key_83ab = { d7 c3 [2] a3 db [2] e4 d9 [2] a3 c8 [2] ed c4 [2] e1 ce [2] f6 c5 [2] ed 8b [2] d0 }

  condition:
    any of them
}