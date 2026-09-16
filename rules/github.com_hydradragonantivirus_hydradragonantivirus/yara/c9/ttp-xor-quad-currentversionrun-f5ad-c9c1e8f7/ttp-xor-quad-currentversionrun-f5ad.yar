rule TTP_XOR_QUAD_CurrentVersionRun_f5ad {
  strings:
    $key_f5ad = { a6 c2 [2] 82 cc [2] a9 e0 [2] 87 c2 [2] 93 d9 [2] 9c c3 [2] 82 de [2] 80 df [2] 9b d9 [2] 87 de [2] 9b f1 }

  condition:
    any of them
}