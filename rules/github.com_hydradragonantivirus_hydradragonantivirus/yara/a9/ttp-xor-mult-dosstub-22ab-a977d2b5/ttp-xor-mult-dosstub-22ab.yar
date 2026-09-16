rule TTP_XOR_MULT_DOSStub_22ab {
  strings:
    $key_22ab = { 76 c3 [2] 02 db [2] 45 d9 [2] 02 c8 [2] 4c c4 [2] 40 ce [2] 57 c5 [2] 4c 8b [2] 71 }

  condition:
    any of them
}