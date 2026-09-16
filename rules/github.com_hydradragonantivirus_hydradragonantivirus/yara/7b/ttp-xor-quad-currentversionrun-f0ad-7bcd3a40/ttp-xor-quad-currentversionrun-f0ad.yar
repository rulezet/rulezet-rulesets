rule TTP_XOR_QUAD_CurrentVersionRun_f0ad {
  strings:
    $key_f0ad = { a3 c2 [2] 87 cc [2] ac e0 [2] 82 c2 [2] 96 d9 [2] 99 c3 [2] 87 de [2] 85 df [2] 9e d9 [2] 82 de [2] 9e f1 }

  condition:
    any of them
}