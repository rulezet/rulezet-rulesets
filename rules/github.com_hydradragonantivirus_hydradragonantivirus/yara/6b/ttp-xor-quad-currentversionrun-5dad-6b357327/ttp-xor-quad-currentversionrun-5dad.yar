rule TTP_XOR_QUAD_CurrentVersionRun_5dad {
  strings:
    $key_5dad = { 0e c2 [2] 2a cc [2] 01 e0 [2] 2f c2 [2] 3b d9 [2] 34 c3 [2] 2a de [2] 28 df [2] 33 d9 [2] 2f de [2] 33 f1 }

  condition:
    any of them
}