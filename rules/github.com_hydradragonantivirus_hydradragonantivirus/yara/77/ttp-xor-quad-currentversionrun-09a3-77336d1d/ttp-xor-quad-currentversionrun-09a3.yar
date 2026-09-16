rule TTP_XOR_QUAD_CurrentVersionRun_09a3 {
  strings:
    $key_09a3 = { 5a cc [2] 7e c2 [2] 55 ee [2] 7b cc [2] 6f d7 [2] 60 cd [2] 7e d0 [2] 7c d1 [2] 67 d7 [2] 7b d0 [2] 67 ff }

  condition:
    any of them
}