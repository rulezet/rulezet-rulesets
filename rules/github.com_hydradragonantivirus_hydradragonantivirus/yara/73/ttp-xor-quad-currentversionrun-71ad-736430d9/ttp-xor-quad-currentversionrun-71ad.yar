rule TTP_XOR_QUAD_CurrentVersionRun_71ad {
  strings:
    $key_71ad = { 22 c2 [2] 06 cc [2] 2d e0 [2] 03 c2 [2] 17 d9 [2] 18 c3 [2] 06 de [2] 04 df [2] 1f d9 [2] 03 de [2] 1f f1 }

  condition:
    any of them
}