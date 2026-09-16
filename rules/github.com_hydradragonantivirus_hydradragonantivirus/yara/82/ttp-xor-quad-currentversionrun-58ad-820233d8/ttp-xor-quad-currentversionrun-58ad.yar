rule TTP_XOR_QUAD_CurrentVersionRun_58ad {
  strings:
    $key_58ad = { 0b c2 [2] 2f cc [2] 04 e0 [2] 2a c2 [2] 3e d9 [2] 31 c3 [2] 2f de [2] 2d df [2] 36 d9 [2] 2a de [2] 36 f1 }

  condition:
    any of them
}