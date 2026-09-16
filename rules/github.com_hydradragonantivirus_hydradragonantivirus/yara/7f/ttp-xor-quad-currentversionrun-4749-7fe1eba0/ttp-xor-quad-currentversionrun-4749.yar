rule TTP_XOR_QUAD_CurrentVersionRun_4749 {
  strings:
    $key_4749 = { 14 26 [2] 30 28 [2] 1b 04 [2] 35 26 [2] 21 3d [2] 2e 27 [2] 30 3a [2] 32 3b [2] 29 3d [2] 35 3a [2] 29 15 }

  condition:
    any of them
}