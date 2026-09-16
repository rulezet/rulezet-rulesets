rule TTP_XOR_QUAD_CurrentVersionRun_4ca3 {
  strings:
    $key_4ca3 = { 1f cc [2] 3b c2 [2] 10 ee [2] 3e cc [2] 2a d7 [2] 25 cd [2] 3b d0 [2] 39 d1 [2] 22 d7 [2] 3e d0 [2] 22 ff }

  condition:
    any of them
}