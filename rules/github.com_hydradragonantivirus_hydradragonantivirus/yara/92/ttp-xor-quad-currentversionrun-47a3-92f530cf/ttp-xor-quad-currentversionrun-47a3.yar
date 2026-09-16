rule TTP_XOR_QUAD_CurrentVersionRun_47a3 {
  strings:
    $key_47a3 = { 14 cc [2] 30 c2 [2] 1b ee [2] 35 cc [2] 21 d7 [2] 2e cd [2] 30 d0 [2] 32 d1 [2] 29 d7 [2] 35 d0 [2] 29 ff }

  condition:
    any of them
}