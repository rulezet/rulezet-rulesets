rule TTP_XOR_MULT_DOSStub_23ab {
  strings:
    $key_23ab = { 77 c3 [2] 03 db [2] 44 d9 [2] 03 c8 [2] 4d c4 [2] 41 ce [2] 56 c5 [2] 4d 8b [2] 70 }

  condition:
    any of them
}