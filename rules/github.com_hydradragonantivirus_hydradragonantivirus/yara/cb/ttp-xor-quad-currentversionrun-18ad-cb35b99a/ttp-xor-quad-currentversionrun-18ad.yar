rule TTP_XOR_QUAD_CurrentVersionRun_18ad {
  strings:
    $key_18ad = { 4b c2 [2] 6f cc [2] 44 e0 [2] 6a c2 [2] 7e d9 [2] 71 c3 [2] 6f de [2] 6d df [2] 76 d9 [2] 6a de [2] 76 f1 }

  condition:
    any of them
}