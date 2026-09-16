rule TTP_XOR_MULT_DOSStub_c3ab {
  strings:
    $key_c3ab = { 97 c3 [2] e3 db [2] a4 d9 [2] e3 c8 [2] ad c4 [2] a1 ce [2] b6 c5 [2] ad 8b [2] 90 }

  condition:
    any of them
}