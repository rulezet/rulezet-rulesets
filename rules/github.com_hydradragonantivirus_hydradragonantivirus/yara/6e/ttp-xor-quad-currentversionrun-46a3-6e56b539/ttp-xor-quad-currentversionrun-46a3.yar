rule TTP_XOR_QUAD_CurrentVersionRun_46a3 {
  strings:
    $key_46a3 = { 15 cc [2] 31 c2 [2] 1a ee [2] 34 cc [2] 20 d7 [2] 2f cd [2] 31 d0 [2] 33 d1 [2] 28 d7 [2] 34 d0 [2] 28 ff }

  condition:
    any of them
}