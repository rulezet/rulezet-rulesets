rule TTP_XOR_QUAD_CurrentVersionRun_13a3 {
  strings:
    $key_13a3 = { 40 cc [2] 64 c2 [2] 4f ee [2] 61 cc [2] 75 d7 [2] 7a cd [2] 64 d0 [2] 66 d1 [2] 7d d7 [2] 61 d0 [2] 7d ff }

  condition:
    any of them
}