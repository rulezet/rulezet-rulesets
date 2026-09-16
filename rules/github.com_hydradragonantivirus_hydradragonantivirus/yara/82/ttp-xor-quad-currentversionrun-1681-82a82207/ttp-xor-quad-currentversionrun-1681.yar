rule TTP_XOR_QUAD_CurrentVersionRun_1681 {
  strings:
    $key_1681 = { 45 ee [2] 61 e0 [2] 4a cc [2] 64 ee [2] 70 f5 [2] 7f ef [2] 61 f2 [2] 63 f3 [2] 78 f5 [2] 64 f2 [2] 78 dd }

  condition:
    any of them
}