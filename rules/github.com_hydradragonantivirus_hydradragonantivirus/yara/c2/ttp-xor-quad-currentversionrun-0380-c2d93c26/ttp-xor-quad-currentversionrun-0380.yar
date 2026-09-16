rule TTP_XOR_QUAD_CurrentVersionRun_0380 {
  strings:
    $key_0380 = { 50 ef [2] 74 e1 [2] 5f cd [2] 71 ef [2] 65 f4 [2] 6a ee [2] 74 f3 [2] 76 f2 [2] 6d f4 [2] 71 f3 [2] 6d dc }

  condition:
    any of them
}