rule TTP_XOR_QUAD_CurrentVersionRun_2f49 {
  strings:
    $key_2f49 = { 7c 26 [2] 58 28 [2] 73 04 [2] 5d 26 [2] 49 3d [2] 46 27 [2] 58 3a [2] 5a 3b [2] 41 3d [2] 5d 3a [2] 41 15 }

  condition:
    any of them
}