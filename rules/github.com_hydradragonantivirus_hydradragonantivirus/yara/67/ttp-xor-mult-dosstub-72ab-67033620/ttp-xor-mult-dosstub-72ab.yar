rule TTP_XOR_MULT_DOSStub_72ab {
  strings:
    $key_72ab = { 26 c3 [2] 52 db [2] 15 d9 [2] 52 c8 [2] 1c c4 [2] 10 ce [2] 07 c5 [2] 1c 8b [2] 21 }

  condition:
    any of them
}