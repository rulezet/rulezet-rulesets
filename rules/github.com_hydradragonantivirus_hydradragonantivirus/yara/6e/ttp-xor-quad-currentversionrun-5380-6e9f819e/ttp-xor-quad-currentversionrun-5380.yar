rule TTP_XOR_QUAD_CurrentVersionRun_5380 {
  strings:
    $key_5380 = { 00 ef [2] 24 e1 [2] 0f cd [2] 21 ef [2] 35 f4 [2] 3a ee [2] 24 f3 [2] 26 f2 [2] 3d f4 [2] 21 f3 [2] 3d dc }

  condition:
    any of them
}