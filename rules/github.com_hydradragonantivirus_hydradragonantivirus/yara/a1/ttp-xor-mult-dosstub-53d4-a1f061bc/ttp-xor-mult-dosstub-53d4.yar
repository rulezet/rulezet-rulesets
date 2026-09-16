rule TTP_XOR_MULT_DOSStub_53d4 {
  strings:
    $key_53d4 = { 07 bc [2] 73 a4 [2] 34 a6 [2] 73 b7 [2] 3d bb [2] 31 b1 [2] 26 ba [2] 3d f4 [2] 00 }

  condition:
    any of them
}