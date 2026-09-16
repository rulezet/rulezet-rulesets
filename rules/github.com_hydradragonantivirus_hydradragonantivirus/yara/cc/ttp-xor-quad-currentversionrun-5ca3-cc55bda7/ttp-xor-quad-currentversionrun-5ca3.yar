rule TTP_XOR_QUAD_CurrentVersionRun_5ca3 {
  strings:
    $key_5ca3 = { 0f cc [2] 2b c2 [2] 00 ee [2] 2e cc [2] 3a d7 [2] 35 cd [2] 2b d0 [2] 29 d1 [2] 32 d7 [2] 2e d0 [2] 32 ff }

  condition:
    any of them
}