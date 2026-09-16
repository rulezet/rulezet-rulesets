rule TTP_XOR_QUAD_CurrentVersionRun_1fa3 {
  strings:
    $key_1fa3 = { 4c cc [2] 68 c2 [2] 43 ee [2] 6d cc [2] 79 d7 [2] 76 cd [2] 68 d0 [2] 6a d1 [2] 71 d7 [2] 6d d0 [2] 71 ff }

  condition:
    any of them
}