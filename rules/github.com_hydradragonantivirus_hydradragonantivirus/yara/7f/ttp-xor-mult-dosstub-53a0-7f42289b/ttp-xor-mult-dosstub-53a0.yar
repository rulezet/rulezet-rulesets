rule TTP_XOR_MULT_DOSStub_53a0 {
  strings:
    $key_53a0 = { 07 c8 [2] 73 d0 [2] 34 d2 [2] 73 c3 [2] 3d cf [2] 31 c5 [2] 26 ce [2] 3d 80 [2] 00 }

  condition:
    any of them
}