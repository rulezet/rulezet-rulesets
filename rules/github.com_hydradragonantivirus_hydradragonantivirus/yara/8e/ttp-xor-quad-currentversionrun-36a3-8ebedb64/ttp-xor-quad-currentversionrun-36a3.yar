rule TTP_XOR_QUAD_CurrentVersionRun_36a3 {
  strings:
    $key_36a3 = { 65 cc [2] 41 c2 [2] 6a ee [2] 44 cc [2] 50 d7 [2] 5f cd [2] 41 d0 [2] 43 d1 [2] 58 d7 [2] 44 d0 [2] 58 ff }

  condition:
    any of them
}