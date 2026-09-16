rule TTP_XOR_MULT_DOSStub_71ab {
  strings:
    $key_71ab = { 25 c3 [2] 51 db [2] 16 d9 [2] 51 c8 [2] 1f c4 [2] 13 ce [2] 04 c5 [2] 1f 8b [2] 22 }

  condition:
    any of them
}