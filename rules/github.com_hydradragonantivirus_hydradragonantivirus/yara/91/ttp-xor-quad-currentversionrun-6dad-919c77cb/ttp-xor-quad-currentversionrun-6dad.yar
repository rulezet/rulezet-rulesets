rule TTP_XOR_QUAD_CurrentVersionRun_6dad {
  strings:
    $key_6dad = { 3e c2 [2] 1a cc [2] 31 e0 [2] 1f c2 [2] 0b d9 [2] 04 c3 [2] 1a de [2] 18 df [2] 03 d9 [2] 1f de [2] 03 f1 }

  condition:
    any of them
}