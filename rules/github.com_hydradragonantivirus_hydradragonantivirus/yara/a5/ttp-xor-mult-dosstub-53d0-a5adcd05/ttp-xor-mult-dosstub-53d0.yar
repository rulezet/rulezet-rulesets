rule TTP_XOR_MULT_DOSStub_53d0 {
  strings:
    $key_53d0 = { 07 b8 [2] 73 a0 [2] 34 a2 [2] 73 b3 [2] 3d bf [2] 31 b5 [2] 26 be [2] 3d f0 [2] 00 }

  condition:
    any of them
}