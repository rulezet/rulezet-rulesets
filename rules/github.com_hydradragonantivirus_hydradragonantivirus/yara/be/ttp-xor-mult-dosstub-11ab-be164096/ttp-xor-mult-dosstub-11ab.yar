rule TTP_XOR_MULT_DOSStub_11ab {
  strings:
    $key_11ab = { 45 c3 [2] 31 db [2] 76 d9 [2] 31 c8 [2] 7f c4 [2] 73 ce [2] 64 c5 [2] 7f 8b [2] 42 }

  condition:
    any of them
}