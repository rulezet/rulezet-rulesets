rule TTP_XOR_QUAD_CurrentVersionRun_58a3 {
  strings:
    $key_58a3 = { 0b cc [2] 2f c2 [2] 04 ee [2] 2a cc [2] 3e d7 [2] 31 cd [2] 2f d0 [2] 2d d1 [2] 36 d7 [2] 2a d0 [2] 36 ff }

  condition:
    any of them
}