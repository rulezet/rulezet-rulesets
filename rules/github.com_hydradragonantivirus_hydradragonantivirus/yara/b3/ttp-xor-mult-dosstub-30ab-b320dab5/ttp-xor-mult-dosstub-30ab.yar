rule TTP_XOR_MULT_DOSStub_30ab {
  strings:
    $key_30ab = { 64 c3 [2] 10 db [2] 57 d9 [2] 10 c8 [2] 5e c4 [2] 52 ce [2] 45 c5 [2] 5e 8b [2] 63 }

  condition:
    any of them
}