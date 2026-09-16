rule TTP_XOR_QUAD_CurrentVersionRun_03a3 {
  strings:
    $key_03a3 = { 50 cc [2] 74 c2 [2] 5f ee [2] 71 cc [2] 65 d7 [2] 6a cd [2] 74 d0 [2] 76 d1 [2] 6d d7 [2] 71 d0 [2] 6d ff }

  condition:
    any of them
}