rule TTP_XOR_QUAD_CurrentVersionRun_56a3 {
  strings:
    $key_56a3 = { 05 cc [2] 21 c2 [2] 0a ee [2] 24 cc [2] 30 d7 [2] 3f cd [2] 21 d0 [2] 23 d1 [2] 38 d7 [2] 24 d0 [2] 38 ff }

  condition:
    any of them
}