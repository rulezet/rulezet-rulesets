rule TTP_XOR_QUAD_CurrentVersionRun_6380 {
  strings:
    $key_6380 = { 30 ef [2] 14 e1 [2] 3f cd [2] 11 ef [2] 05 f4 [2] 0a ee [2] 14 f3 [2] 16 f2 [2] 0d f4 [2] 11 f3 [2] 0d dc }

  condition:
    any of them
}