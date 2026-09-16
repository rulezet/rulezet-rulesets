rule TTP_XOR_QUAD_CurrentVersionRun_07ad {
  strings:
    $key_07ad = { 54 c2 [2] 70 cc [2] 5b e0 [2] 75 c2 [2] 61 d9 [2] 6e c3 [2] 70 de [2] 72 df [2] 69 d9 [2] 75 de [2] 69 f1 }

  condition:
    any of them
}