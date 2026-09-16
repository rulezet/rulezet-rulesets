rule TTP_XOR_QUAD_CurrentVersionRun_3449 {
  strings:
    $key_3449 = { 67 26 [2] 43 28 [2] 68 04 [2] 46 26 [2] 52 3d [2] 5d 27 [2] 43 3a [2] 41 3b [2] 5a 3d [2] 46 3a [2] 5a 15 }

  condition:
    any of them
}