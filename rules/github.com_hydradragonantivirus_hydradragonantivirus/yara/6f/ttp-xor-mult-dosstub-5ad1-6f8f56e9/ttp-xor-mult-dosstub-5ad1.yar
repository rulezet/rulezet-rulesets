rule TTP_XOR_MULT_DOSStub_5ad1 {
  strings:
    $key_5ad1 = { 0e b9 [2] 7a a1 [2] 3d a3 [2] 7a b2 [2] 34 be [2] 38 b4 [2] 2f bf [2] 34 f1 [2] 09 }

  condition:
    any of them
}