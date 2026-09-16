rule TTP_XOR_MULT_DOSStub_5ad3 {
  strings:
    $key_5ad3 = { 0e bb [2] 7a a3 [2] 3d a1 [2] 7a b0 [2] 34 bc [2] 38 b6 [2] 2f bd [2] 34 f3 [2] 09 }

  condition:
    any of them
}