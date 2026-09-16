rule TTP_XOR_MULT_DOSStub_64ab {
  strings:
    $key_64ab = { 30 c3 [2] 44 db [2] 03 d9 [2] 44 c8 [2] 0a c4 [2] 06 ce [2] 11 c5 [2] 0a 8b [2] 37 }

  condition:
    any of them
}