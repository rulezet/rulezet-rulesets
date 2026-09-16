rule TTP_XOR_MULT_DOSStub_d6ab {
  strings:
    $key_d6ab = { 82 c3 [2] f6 db [2] b1 d9 [2] f6 c8 [2] b8 c4 [2] b4 ce [2] a3 c5 [2] b8 8b [2] 85 }

  condition:
    any of them
}