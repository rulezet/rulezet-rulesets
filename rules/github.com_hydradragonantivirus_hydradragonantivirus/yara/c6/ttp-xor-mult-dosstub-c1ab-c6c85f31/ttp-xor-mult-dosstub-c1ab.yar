rule TTP_XOR_MULT_DOSStub_c1ab {
  strings:
    $key_c1ab = { 95 c3 [2] e1 db [2] a6 d9 [2] e1 c8 [2] af c4 [2] a3 ce [2] b4 c5 [2] af 8b [2] 92 }

  condition:
    any of them
}