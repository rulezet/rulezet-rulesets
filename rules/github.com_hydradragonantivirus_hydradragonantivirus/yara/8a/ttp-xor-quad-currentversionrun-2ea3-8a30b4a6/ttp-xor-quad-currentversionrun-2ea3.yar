rule TTP_XOR_QUAD_CurrentVersionRun_2ea3 {
  strings:
    $key_2ea3 = { 7d cc [2] 59 c2 [2] 72 ee [2] 5c cc [2] 48 d7 [2] 47 cd [2] 59 d0 [2] 5b d1 [2] 40 d7 [2] 5c d0 [2] 40 ff }

  condition:
    any of them
}