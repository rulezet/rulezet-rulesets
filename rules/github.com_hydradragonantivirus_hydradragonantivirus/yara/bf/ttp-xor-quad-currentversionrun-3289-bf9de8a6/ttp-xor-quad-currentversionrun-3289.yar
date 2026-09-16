rule TTP_XOR_QUAD_CurrentVersionRun_3289 {
  strings:
    $key_3289 = { 61 e6 [2] 45 e8 [2] 6e c4 [2] 40 e6 [2] 54 fd [2] 5b e7 [2] 45 fa [2] 47 fb [2] 5c fd [2] 40 fa [2] 5c d5 }

  condition:
    any of them
}