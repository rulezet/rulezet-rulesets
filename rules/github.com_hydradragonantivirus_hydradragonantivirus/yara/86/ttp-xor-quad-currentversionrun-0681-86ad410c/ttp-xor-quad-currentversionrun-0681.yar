rule TTP_XOR_QUAD_CurrentVersionRun_0681 {
  strings:
    $key_0681 = { 55 ee [2] 71 e0 [2] 5a cc [2] 74 ee [2] 60 f5 [2] 6f ef [2] 71 f2 [2] 73 f3 [2] 68 f5 [2] 74 f2 [2] 68 dd }

  condition:
    any of them
}