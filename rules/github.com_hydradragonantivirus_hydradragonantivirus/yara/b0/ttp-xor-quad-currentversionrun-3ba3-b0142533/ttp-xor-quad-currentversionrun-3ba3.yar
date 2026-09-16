rule TTP_XOR_QUAD_CurrentVersionRun_3ba3 {
  strings:
    $key_3ba3 = { 68 cc [2] 4c c2 [2] 67 ee [2] 49 cc [2] 5d d7 [2] 52 cd [2] 4c d0 [2] 4e d1 [2] 55 d7 [2] 49 d0 [2] 55 ff }

  condition:
    any of them
}