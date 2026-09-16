rule TTP_XOR_MULT_DOSStub_75ab {
  strings:
    $key_75ab = { 21 c3 [2] 55 db [2] 12 d9 [2] 55 c8 [2] 1b c4 [2] 17 ce [2] 00 c5 [2] 1b 8b [2] 26 }

  condition:
    any of them
}