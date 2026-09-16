rule TTP_XOR_MULT_DOSStub_53c0 {
  strings:
    $key_53c0 = { 07 a8 [2] 73 b0 [2] 34 b2 [2] 73 a3 [2] 3d af [2] 31 a5 [2] 26 ae [2] 3d e0 [2] 00 }

  condition:
    any of them
}