rule TTP_XOR_MULT_DOSStub_54ab {
  strings:
    $key_54ab = { 00 c3 [2] 74 db [2] 33 d9 [2] 74 c8 [2] 3a c4 [2] 36 ce [2] 21 c5 [2] 3a 8b [2] 07 }

  condition:
    any of them
}