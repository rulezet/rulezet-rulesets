rule TTP_XOR_MULT_DOSStub_e7ab {
  strings:
    $key_e7ab = { b3 c3 [2] c7 db [2] 80 d9 [2] c7 c8 [2] 89 c4 [2] 85 ce [2] 92 c5 [2] 89 8b [2] b4 }

  condition:
    any of them
}