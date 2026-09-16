rule TTP_XOR_MULT_DOSStub_67ab {
  strings:
    $key_67ab = { 33 c3 [2] 47 db [2] 00 d9 [2] 47 c8 [2] 09 c4 [2] 05 ce [2] 12 c5 [2] 09 8b [2] 34 }

  condition:
    any of them
}