rule TTP_XOR_QUAD_CurrentVersionRun_7ca3 {
  strings:
    $key_7ca3 = { 2f cc [2] 0b c2 [2] 20 ee [2] 0e cc [2] 1a d7 [2] 15 cd [2] 0b d0 [2] 09 d1 [2] 12 d7 [2] 0e d0 [2] 12 ff }

  condition:
    any of them
}