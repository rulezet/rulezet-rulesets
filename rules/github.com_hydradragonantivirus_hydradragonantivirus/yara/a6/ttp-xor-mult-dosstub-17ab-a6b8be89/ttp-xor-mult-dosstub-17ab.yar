rule TTP_XOR_MULT_DOSStub_17ab {
  strings:
    $key_17ab = { 43 c3 [2] 37 db [2] 70 d9 [2] 37 c8 [2] 79 c4 [2] 75 ce [2] 62 c5 [2] 79 8b [2] 44 }

  condition:
    any of them
}