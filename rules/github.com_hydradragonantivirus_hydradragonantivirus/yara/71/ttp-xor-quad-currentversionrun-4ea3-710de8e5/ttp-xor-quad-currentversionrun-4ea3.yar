rule TTP_XOR_QUAD_CurrentVersionRun_4ea3 {
  strings:
    $key_4ea3 = { 1d cc [2] 39 c2 [2] 12 ee [2] 3c cc [2] 28 d7 [2] 27 cd [2] 39 d0 [2] 3b d1 [2] 20 d7 [2] 3c d0 [2] 20 ff }

  condition:
    any of them
}