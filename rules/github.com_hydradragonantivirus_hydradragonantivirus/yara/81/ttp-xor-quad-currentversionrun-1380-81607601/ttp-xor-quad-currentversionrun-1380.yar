rule TTP_XOR_QUAD_CurrentVersionRun_1380 {
  strings:
    $key_1380 = { 40 ef [2] 64 e1 [2] 4f cd [2] 61 ef [2] 75 f4 [2] 7a ee [2] 64 f3 [2] 66 f2 [2] 7d f4 [2] 61 f3 [2] 7d dc }

  condition:
    any of them
}