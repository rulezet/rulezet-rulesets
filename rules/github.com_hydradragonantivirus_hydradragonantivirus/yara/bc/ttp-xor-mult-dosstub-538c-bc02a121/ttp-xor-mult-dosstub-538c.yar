rule TTP_XOR_MULT_DOSStub_538c {
  strings:
    $key_538c = { 07 e4 [2] 73 fc [2] 34 fe [2] 73 ef [2] 3d e3 [2] 31 e9 [2] 26 e2 [2] 3d ac [2] 00 }

  condition:
    any of them
}