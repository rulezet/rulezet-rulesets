rule TTP_XOR_QUAD_CurrentVersionRun_49a3 {
  strings:
    $key_49a3 = { 1a cc [2] 3e c2 [2] 15 ee [2] 3b cc [2] 2f d7 [2] 20 cd [2] 3e d0 [2] 3c d1 [2] 27 d7 [2] 3b d0 [2] 27 ff }

  condition:
    any of them
}