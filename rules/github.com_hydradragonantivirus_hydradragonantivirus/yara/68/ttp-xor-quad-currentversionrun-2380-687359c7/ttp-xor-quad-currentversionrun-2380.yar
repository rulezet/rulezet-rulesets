rule TTP_XOR_QUAD_CurrentVersionRun_2380 {
  strings:
    $key_2380 = { 70 ef [2] 54 e1 [2] 7f cd [2] 51 ef [2] 45 f4 [2] 4a ee [2] 54 f3 [2] 56 f2 [2] 4d f4 [2] 51 f3 [2] 4d dc }

  condition:
    any of them
}