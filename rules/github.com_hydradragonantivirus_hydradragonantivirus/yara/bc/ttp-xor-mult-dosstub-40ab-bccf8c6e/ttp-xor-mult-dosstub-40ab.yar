rule TTP_XOR_MULT_DOSStub_40ab {
  strings:
    $key_40ab = { 14 c3 [2] 60 db [2] 27 d9 [2] 60 c8 [2] 2e c4 [2] 22 ce [2] 35 c5 [2] 2e 8b [2] 13 }

  condition:
    any of them
}