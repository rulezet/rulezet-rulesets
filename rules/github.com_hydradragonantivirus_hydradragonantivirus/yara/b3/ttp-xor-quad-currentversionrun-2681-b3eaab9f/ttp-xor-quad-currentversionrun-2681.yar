rule TTP_XOR_QUAD_CurrentVersionRun_2681 {
  strings:
    $key_2681 = { 75 ee [2] 51 e0 [2] 7a cc [2] 54 ee [2] 40 f5 [2] 4f ef [2] 51 f2 [2] 53 f3 [2] 48 f5 [2] 54 f2 [2] 48 dd }

  condition:
    any of them
}