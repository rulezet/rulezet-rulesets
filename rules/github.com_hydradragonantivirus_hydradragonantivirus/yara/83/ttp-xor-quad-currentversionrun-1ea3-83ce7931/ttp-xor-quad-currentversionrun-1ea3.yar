rule TTP_XOR_QUAD_CurrentVersionRun_1ea3 {
  strings:
    $key_1ea3 = { 4d cc [2] 69 c2 [2] 42 ee [2] 6c cc [2] 78 d7 [2] 77 cd [2] 69 d0 [2] 6b d1 [2] 70 d7 [2] 6c d0 [2] 70 ff }

  condition:
    any of them
}