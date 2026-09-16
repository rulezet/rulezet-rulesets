rule TTP_XOR_MULT_DOSStub_53a2 {
  strings:
    $key_53a2 = { 07 ca [2] 73 d2 [2] 34 d0 [2] 73 c1 [2] 3d cd [2] 31 c7 [2] 26 cc [2] 3d 82 [2] 00 }

  condition:
    any of them
}