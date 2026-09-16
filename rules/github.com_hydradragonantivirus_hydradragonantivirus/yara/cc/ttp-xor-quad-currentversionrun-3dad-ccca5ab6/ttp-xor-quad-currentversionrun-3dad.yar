rule TTP_XOR_QUAD_CurrentVersionRun_3dad {
  strings:
    $key_3dad = { 6e c2 [2] 4a cc [2] 61 e0 [2] 4f c2 [2] 5b d9 [2] 54 c3 [2] 4a de [2] 48 df [2] 53 d9 [2] 4f de [2] 53 f1 }

  condition:
    any of them
}