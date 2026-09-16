rule TTP_XOR_QUAD_CurrentVersionRun_3ca3 {
  strings:
    $key_3ca3 = { 6f cc [2] 4b c2 [2] 60 ee [2] 4e cc [2] 5a d7 [2] 55 cd [2] 4b d0 [2] 49 d1 [2] 52 d7 [2] 4e d0 [2] 52 ff }

  condition:
    any of them
}