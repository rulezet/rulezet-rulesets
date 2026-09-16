rule TTP_XOR_QUAD_CurrentVersionRun_4fa3 {
  strings:
    $key_4fa3 = { 1c cc [2] 38 c2 [2] 13 ee [2] 3d cc [2] 29 d7 [2] 26 cd [2] 38 d0 [2] 3a d1 [2] 21 d7 [2] 3d d0 [2] 21 ff }

  condition:
    any of them
}