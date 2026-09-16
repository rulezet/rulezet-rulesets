rule TTP_XOR_MULT_DOSStub_21ab {
  strings:
    $key_21ab = { 75 c3 [2] 01 db [2] 46 d9 [2] 01 c8 [2] 4f c4 [2] 43 ce [2] 54 c5 [2] 4f 8b [2] 72 }

  condition:
    any of them
}