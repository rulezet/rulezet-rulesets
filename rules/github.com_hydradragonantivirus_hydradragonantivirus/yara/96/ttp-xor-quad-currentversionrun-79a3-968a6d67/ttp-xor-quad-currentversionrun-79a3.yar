rule TTP_XOR_QUAD_CurrentVersionRun_79a3 {
  strings:
    $key_79a3 = { 2a cc [2] 0e c2 [2] 25 ee [2] 0b cc [2] 1f d7 [2] 10 cd [2] 0e d0 [2] 0c d1 [2] 17 d7 [2] 0b d0 [2] 17 ff }

  condition:
    any of them
}