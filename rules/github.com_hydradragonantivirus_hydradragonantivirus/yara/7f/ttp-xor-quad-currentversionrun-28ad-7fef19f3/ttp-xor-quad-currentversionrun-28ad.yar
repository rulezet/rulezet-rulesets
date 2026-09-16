rule TTP_XOR_QUAD_CurrentVersionRun_28ad {
  strings:
    $key_28ad = { 7b c2 [2] 5f cc [2] 74 e0 [2] 5a c2 [2] 4e d9 [2] 41 c3 [2] 5f de [2] 5d df [2] 46 d9 [2] 5a de [2] 46 f1 }

  condition:
    any of them
}