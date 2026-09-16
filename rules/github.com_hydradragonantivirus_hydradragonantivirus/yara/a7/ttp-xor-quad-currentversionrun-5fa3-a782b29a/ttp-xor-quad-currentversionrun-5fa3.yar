rule TTP_XOR_QUAD_CurrentVersionRun_5fa3 {
  strings:
    $key_5fa3 = { 0c cc [2] 28 c2 [2] 03 ee [2] 2d cc [2] 39 d7 [2] 36 cd [2] 28 d0 [2] 2a d1 [2] 31 d7 [2] 2d d0 [2] 31 ff }

  condition:
    any of them
}