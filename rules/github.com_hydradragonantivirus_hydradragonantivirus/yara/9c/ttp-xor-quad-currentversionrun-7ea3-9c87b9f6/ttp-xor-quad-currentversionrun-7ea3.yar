rule TTP_XOR_QUAD_CurrentVersionRun_7ea3 {
  strings:
    $key_7ea3 = { 2d cc [2] 09 c2 [2] 22 ee [2] 0c cc [2] 18 d7 [2] 17 cd [2] 09 d0 [2] 0b d1 [2] 10 d7 [2] 0c d0 [2] 10 ff }

  condition:
    any of them
}