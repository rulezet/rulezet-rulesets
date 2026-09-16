rule TTP_XOR_QUAD_CurrentVersionRun_f2ad {
  strings:
    $key_f2ad = { a1 c2 [2] 85 cc [2] ae e0 [2] 80 c2 [2] 94 d9 [2] 9b c3 [2] 85 de [2] 87 df [2] 9c d9 [2] 80 de [2] 9c f1 }

  condition:
    any of them
}