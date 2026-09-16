rule TTP_XOR_QUAD_CurrentVersionRun_3681 {
  strings:
    $key_3681 = { 65 ee [2] 41 e0 [2] 6a cc [2] 44 ee [2] 50 f5 [2] 5f ef [2] 41 f2 [2] 43 f3 [2] 58 f5 [2] 44 f2 [2] 58 dd }

  condition:
    any of them
}