rule TTP_XOR_QUAD_CurrentVersionRun_7dad {
  strings:
    $key_7dad = { 2e c2 [2] 0a cc [2] 21 e0 [2] 0f c2 [2] 1b d9 [2] 14 c3 [2] 0a de [2] 08 df [2] 13 d9 [2] 0f de [2] 13 f1 }

  condition:
    any of them
}