rule TTP_XOR_MULT_DOSStub_74ab {
  strings:
    $key_74ab = { 20 c3 [2] 54 db [2] 13 d9 [2] 54 c8 [2] 1a c4 [2] 16 ce [2] 01 c5 [2] 1a 8b [2] 27 }

  condition:
    any of them
}