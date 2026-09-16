rule TTP_XOR_MULT_DOSStub_6987 {
  strings:
    $key_6987 = { 3d ef [2] 49 f7 [2] 0e f5 [2] 49 e4 [2] 07 e8 [2] 0b e2 [2] 1c e9 [2] 07 a7 [2] 3a }

  condition:
    any of them
}