rule TTP_XOR_QUAD_CurrentVersionRun_68a3 {
  strings:
    $key_68a3 = { 3b cc [2] 1f c2 [2] 34 ee [2] 1a cc [2] 0e d7 [2] 01 cd [2] 1f d0 [2] 1d d1 [2] 06 d7 [2] 1a d0 [2] 06 ff }

  condition:
    any of them
}