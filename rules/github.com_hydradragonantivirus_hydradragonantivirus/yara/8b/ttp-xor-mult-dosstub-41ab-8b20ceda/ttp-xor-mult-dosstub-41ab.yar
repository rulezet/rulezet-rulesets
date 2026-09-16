rule TTP_XOR_MULT_DOSStub_41ab {
  strings:
    $key_41ab = { 15 c3 [2] 61 db [2] 26 d9 [2] 61 c8 [2] 2f c4 [2] 23 ce [2] 34 c5 [2] 2f 8b [2] 12 }

  condition:
    any of them
}