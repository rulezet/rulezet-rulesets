rule TTP_XOR_QUAD_CurrentVersionRun_1a49 {
  strings:
    $key_1a49 = { 49 26 [2] 6d 28 [2] 46 04 [2] 68 26 [2] 7c 3d [2] 73 27 [2] 6d 3a [2] 6f 3b [2] 74 3d [2] 68 3a [2] 74 15 }

  condition:
    any of them
}