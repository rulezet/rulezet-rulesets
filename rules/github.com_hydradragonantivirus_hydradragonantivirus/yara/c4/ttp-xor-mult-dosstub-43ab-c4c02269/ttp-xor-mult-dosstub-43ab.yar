rule TTP_XOR_MULT_DOSStub_43ab {
  strings:
    $key_43ab = { 17 c3 [2] 63 db [2] 24 d9 [2] 63 c8 [2] 2d c4 [2] 21 ce [2] 36 c5 [2] 2d 8b [2] 10 }

  condition:
    any of them
}