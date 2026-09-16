rule TTP_XOR_QUAD_CurrentVersionRun_1dad {
  strings:
    $key_1dad = { 4e c2 [2] 6a cc [2] 41 e0 [2] 6f c2 [2] 7b d9 [2] 74 c3 [2] 6a de [2] 68 df [2] 73 d9 [2] 6f de [2] 73 f1 }

  condition:
    any of them
}