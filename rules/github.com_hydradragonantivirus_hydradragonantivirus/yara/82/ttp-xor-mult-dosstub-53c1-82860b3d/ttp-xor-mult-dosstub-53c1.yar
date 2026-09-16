rule TTP_XOR_MULT_DOSStub_53c1 {
  strings:
    $key_53c1 = { 07 a9 [2] 73 b1 [2] 34 b3 [2] 73 a2 [2] 3d ae [2] 31 a4 [2] 26 af [2] 3d e1 [2] 00 }

  condition:
    any of them
}