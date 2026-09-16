rule TTP_XOR_QUAD_CurrentVersionRun_38a3 {
  strings:
    $key_38a3 = { 6b cc [2] 4f c2 [2] 64 ee [2] 4a cc [2] 5e d7 [2] 51 cd [2] 4f d0 [2] 4d d1 [2] 56 d7 [2] 4a d0 [2] 56 ff }

  condition:
    any of them
}