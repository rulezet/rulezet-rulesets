rule TTP_XOR_QUAD_CurrentVersionRun_efa3 {
  strings:
    $key_efa3 = { bc cc [2] 98 c2 [2] b3 ee [2] 9d cc [2] 89 d7 [2] 86 cd [2] 98 d0 [2] 9a d1 [2] 81 d7 [2] 9d d0 [2] 81 ff }

  condition:
    any of them
}