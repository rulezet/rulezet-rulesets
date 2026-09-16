rule TTP_XOR_QUAD_CurrentVersionRun_0dad {
  strings:
    $key_0dad = { 5e c2 [2] 7a cc [2] 51 e0 [2] 7f c2 [2] 6b d9 [2] 64 c3 [2] 7a de [2] 78 df [2] 63 d9 [2] 7f de [2] 63 f1 }

  condition:
    any of them
}