rule TTP_XOR_QUAD_CurrentVersionRun_3ea3 {
  strings:
    $key_3ea3 = { 6d cc [2] 49 c2 [2] 62 ee [2] 4c cc [2] 58 d7 [2] 57 cd [2] 49 d0 [2] 4b d1 [2] 50 d7 [2] 4c d0 [2] 50 ff }

  condition:
    any of them
}