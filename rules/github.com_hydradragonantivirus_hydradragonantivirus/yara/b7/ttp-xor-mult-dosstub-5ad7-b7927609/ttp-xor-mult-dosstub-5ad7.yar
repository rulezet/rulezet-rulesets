rule TTP_XOR_MULT_DOSStub_5ad7 {
  strings:
    $key_5ad7 = { 0e bf [2] 7a a7 [2] 3d a5 [2] 7a b4 [2] 34 b8 [2] 38 b2 [2] 2f b9 [2] 34 f7 [2] 09 }

  condition:
    any of them
}