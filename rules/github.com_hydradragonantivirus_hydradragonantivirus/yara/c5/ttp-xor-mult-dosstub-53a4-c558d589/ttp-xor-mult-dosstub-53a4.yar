rule TTP_XOR_MULT_DOSStub_53a4 {
  strings:
    $key_53a4 = { 07 cc [2] 73 d4 [2] 34 d6 [2] 73 c7 [2] 3d cb [2] 31 c1 [2] 26 ca [2] 3d 84 [2] 00 }

  condition:
    any of them
}