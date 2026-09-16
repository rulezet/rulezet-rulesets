rule TTP_XOR_QUAD_CurrentVersionRun_77ad {
  strings:
    $key_77ad = { 24 c2 [2] 00 cc [2] 2b e0 [2] 05 c2 [2] 11 d9 [2] 1e c3 [2] 00 de [2] 02 df [2] 19 d9 [2] 05 de [2] 19 f1 }

  condition:
    any of them
}