rule TTP_XOR_MULT_DOSStub_5381 {
  strings:
    $key_5381 = { 07 e9 [2] 73 f1 [2] 34 f3 [2] 73 e2 [2] 3d ee [2] 31 e4 [2] 26 ef [2] 3d a1 [2] 00 }

  condition:
    any of them
}