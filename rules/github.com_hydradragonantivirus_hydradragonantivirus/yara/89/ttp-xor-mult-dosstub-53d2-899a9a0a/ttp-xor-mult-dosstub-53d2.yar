rule TTP_XOR_MULT_DOSStub_53d2 {
  strings:
    $key_53d2 = { 07 ba [2] 73 a2 [2] 34 a0 [2] 73 b1 [2] 3d bd [2] 31 b7 [2] 26 bc [2] 3d f2 [2] 00 }

  condition:
    any of them
}