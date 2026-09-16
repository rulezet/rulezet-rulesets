rule TTP_XOR_MULT_DOSStub_53a6 {
  strings:
    $key_53a6 = { 07 ce [2] 73 d6 [2] 34 d4 [2] 73 c5 [2] 3d c9 [2] 31 c3 [2] 26 c8 [2] 3d 86 [2] 00 }

  condition:
    any of them
}