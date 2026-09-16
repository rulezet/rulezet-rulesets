rule TTP_XOR_QUAD_CurrentVersionRun_08a3 {
  strings:
    $key_08a3 = { 5b cc [2] 7f c2 [2] 54 ee [2] 7a cc [2] 6e d7 [2] 61 cd [2] 7f d0 [2] 7d d1 [2] 66 d7 [2] 7a d0 [2] 66 ff }

  condition:
    any of them
}