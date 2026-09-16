rule TTP_XOR_QUAD_CurrentVersionRun_4ba3 {
  strings:
    $key_4ba3 = { 18 cc [2] 3c c2 [2] 17 ee [2] 39 cc [2] 2d d7 [2] 22 cd [2] 3c d0 [2] 3e d1 [2] 25 d7 [2] 39 d0 [2] 25 ff }

  condition:
    any of them
}