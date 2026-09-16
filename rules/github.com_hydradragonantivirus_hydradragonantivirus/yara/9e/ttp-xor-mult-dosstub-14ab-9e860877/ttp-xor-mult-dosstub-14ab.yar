rule TTP_XOR_MULT_DOSStub_14ab {
  strings:
    $key_14ab = { 40 c3 [2] 34 db [2] 73 d9 [2] 34 c8 [2] 7a c4 [2] 76 ce [2] 61 c5 [2] 7a 8b [2] 47 }

  condition:
    any of them
}