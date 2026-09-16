rule TTP_XOR_QUAD_CurrentVersionRun_63a3 {
  strings:
    $key_63a3 = { 30 cc [2] 14 c2 [2] 3f ee [2] 11 cc [2] 05 d7 [2] 0a cd [2] 14 d0 [2] 16 d1 [2] 0d d7 [2] 11 d0 [2] 0d ff }

  condition:
    any of them
}