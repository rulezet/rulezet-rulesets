rule TTP_XOR_MULT_DOSStub_53c5 {
  strings:
    $key_53c5 = { 07 ad [2] 73 b5 [2] 34 b7 [2] 73 a6 [2] 3d aa [2] 31 a0 [2] 26 ab [2] 3d e5 [2] 00 }

  condition:
    any of them
}