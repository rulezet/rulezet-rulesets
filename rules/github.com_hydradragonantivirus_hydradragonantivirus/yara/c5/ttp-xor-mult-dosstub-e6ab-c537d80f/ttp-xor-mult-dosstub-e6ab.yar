rule TTP_XOR_MULT_DOSStub_e6ab {
  strings:
    $key_e6ab = { b2 c3 [2] c6 db [2] 81 d9 [2] c6 c8 [2] 88 c4 [2] 84 ce [2] 93 c5 [2] 88 8b [2] b5 }

  condition:
    any of them
}