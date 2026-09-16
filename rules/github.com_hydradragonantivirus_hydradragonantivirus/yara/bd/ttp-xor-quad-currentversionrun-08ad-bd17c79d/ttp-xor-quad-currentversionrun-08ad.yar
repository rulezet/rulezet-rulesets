rule TTP_XOR_QUAD_CurrentVersionRun_08ad {
  strings:
    $key_08ad = { 5b c2 [2] 7f cc [2] 54 e0 [2] 7a c2 [2] 6e d9 [2] 61 c3 [2] 7f de [2] 7d df [2] 66 d9 [2] 7a de [2] 66 f1 }

  condition:
    any of them
}