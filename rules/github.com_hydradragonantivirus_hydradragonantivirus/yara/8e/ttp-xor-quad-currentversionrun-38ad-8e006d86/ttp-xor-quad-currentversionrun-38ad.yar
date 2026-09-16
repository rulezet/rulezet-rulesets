rule TTP_XOR_QUAD_CurrentVersionRun_38ad {
  strings:
    $key_38ad = { 6b c2 [2] 4f cc [2] 64 e0 [2] 4a c2 [2] 5e d9 [2] 51 c3 [2] 4f de [2] 4d df [2] 56 d9 [2] 4a de [2] 56 f1 }

  condition:
    any of them
}