rule TTP_XOR_QUAD_CurrentVersionRun_59a3 {
  strings:
    $key_59a3 = { 0a cc [2] 2e c2 [2] 05 ee [2] 2b cc [2] 3f d7 [2] 30 cd [2] 2e d0 [2] 2c d1 [2] 37 d7 [2] 2b d0 [2] 37 ff }

  condition:
    any of them
}