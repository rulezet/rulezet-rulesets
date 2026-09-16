rule TTP_XOR_QUAD_CurrentVersionRun_72ad {
  strings:
    $key_72ad = { 21 c2 [2] 05 cc [2] 2e e0 [2] 00 c2 [2] 14 d9 [2] 1b c3 [2] 05 de [2] 07 df [2] 1c d9 [2] 00 de [2] 1c f1 }

  condition:
    any of them
}