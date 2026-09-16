rule TTP_XOR_MULT_DOSStub_96ab {
  strings:
    $key_96ab = { c2 c3 [2] b6 db [2] f1 d9 [2] b6 c8 [2] f8 c4 [2] f4 ce [2] e3 c5 [2] f8 8b [2] c5 }

  condition:
    any of them
}