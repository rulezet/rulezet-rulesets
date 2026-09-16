rule TTP_XOR_QUAD_CurrentVersionRun_4813 {
  strings:
    $key_4813 = { 1b 7c [2] 3f 72 [2] 14 5e [2] 3a 7c [2] 2e 67 [2] 21 7d [2] 3f 60 [2] 3d 61 [2] 26 67 [2] 3a 60 [2] 26 4f }

  condition:
    any of them
}