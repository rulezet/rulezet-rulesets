rule TTP_XOR_QUAD_CurrentVersionRun_57a3 {
  strings:
    $key_57a3 = { 04 cc [2] 20 c2 [2] 0b ee [2] 25 cc [2] 31 d7 [2] 3e cd [2] 20 d0 [2] 22 d1 [2] 39 d7 [2] 25 d0 [2] 39 ff }

  condition:
    any of them
}