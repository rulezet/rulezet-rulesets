rule TTP_XOR_MULT_DOSStub_62ab {
  strings:
    $key_62ab = { 36 c3 [2] 42 db [2] 05 d9 [2] 42 c8 [2] 0c c4 [2] 00 ce [2] 17 c5 [2] 0c 8b [2] 31 }

  condition:
    any of them
}