rule TTP_XOR_MULT_DOSStub_538a {
  strings:
    $key_538a = { 07 e2 [2] 73 fa [2] 34 f8 [2] 73 e9 [2] 3d e5 [2] 31 ef [2] 26 e4 [2] 3d aa [2] 00 }

  condition:
    any of them
}