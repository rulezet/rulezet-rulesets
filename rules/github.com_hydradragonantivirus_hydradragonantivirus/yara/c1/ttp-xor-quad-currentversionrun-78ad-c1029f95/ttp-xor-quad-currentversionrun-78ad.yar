rule TTP_XOR_QUAD_CurrentVersionRun_78ad {
  strings:
    $key_78ad = { 2b c2 [2] 0f cc [2] 24 e0 [2] 0a c2 [2] 1e d9 [2] 11 c3 [2] 0f de [2] 0d df [2] 16 d9 [2] 0a de [2] 16 f1 }

  condition:
    any of them
}