rule TTP_XOR_MULT_DOSStub_07ab {
  strings:
    $key_07ab = { 53 c3 [2] 27 db [2] 60 d9 [2] 27 c8 [2] 69 c4 [2] 65 ce [2] 72 c5 [2] 69 8b [2] 54 }

  condition:
    any of them
}