rule TTP_XOR_MULT_DOSStub_04ab {
  strings:
    $key_04ab = { 50 c3 [2] 24 db [2] 63 d9 [2] 24 c8 [2] 6a c4 [2] 66 ce [2] 71 c5 [2] 6a 8b [2] 57 }

  condition:
    any of them
}