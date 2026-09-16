rule TTP_XOR_MULT_DOSStub_5ad2 {
  strings:
    $key_5ad2 = { 0e ba [2] 7a a2 [2] 3d a0 [2] 7a b1 [2] 34 bd [2] 38 b7 [2] 2f bc [2] 34 f2 [2] 09 }

  condition:
    any of them
}