rule TTP_XOR_QUAD_CurrentVersionRun_3649 {
  strings:
    $key_3649 = { 65 26 [2] 41 28 [2] 6a 04 [2] 44 26 [2] 50 3d [2] 5f 27 [2] 41 3a [2] 43 3b [2] 58 3d [2] 44 3a [2] 58 15 }

  condition:
    any of them
}